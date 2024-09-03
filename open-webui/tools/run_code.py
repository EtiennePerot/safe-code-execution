"""
id: run_code
title: Run code
description: Run arbitrary Python or Bash code safely in a gVisor sandbox.
author: EtiennePerot
author_url: https://github.com/EtiennePerot/open-webui-code-execution
funding_url: https://github.com/EtiennePerot/open-webui-code-execution
version: 0.3.0
license: Apache-2.0
"""

# This is an OpenWebUI *tool*. It allows an LLM to generate and call code on its own.
# If you are looking for an OpenWebUI *function* to allow you to manually execute blocks
# of code in the LLM output, see here instead:
# https://openwebui.com/f/etienneperot/run_code/
# See https://github.com/EtiennePerot/open-webui-code-execution for more info.

# Protip: You can test this tool manually outside of OpenWebUI by running it like this:
#
#   echo 'print("Hello world!")' | python3 run_code.py
#
# This will simulate that OpenWebUI would do if it asked this tool to evaluate the Python code `print("Hello world!")`.
# This can be useful when setting up this tool to verify that it works in your environment.

import asyncio
import collections
import copy
import json
import hashlib
import inspect
import os
import os.path
import platform
import pydantic
import shutil
import subprocess
import sys
import tempfile
import typing
import urllib.request


class Tools:
    class Valves(pydantic.BaseModel):
        NETWORKING_ALLOWED: bool = pydantic.Field(
            default=True,
            description="Whether to allow network access during code execution.",
        )
        MAX_COMMAND_RUNTIME_SECONDS: int = pydantic.Field(
            ge=1,
            default=30,
            description="Maximum number of seconds code is given to run.",
        )
        MAX_COMMAND_RAM_MEGABYTES: int = pydantic.Field(
            ge=0,
            default=0,
            description="Maximum number of megabytes that the interpreter has when running. Must run as root with host cgroups writable (`--cgroupns=host --mount=type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup,readonly=false`) for this to work. Set to 0 to disable memory limits.",
        )
        AUTO_INSTALL: bool = pydantic.Field(
            default=True,
            description="Whether to automatically install gVisor if not installed on the system.",
        )

    def __init__(self):
        self.valves = self.Valves()
        self._debug = False

    async def run_bash_command(
        self,
        bash_command: str,
        __event_emitter__: typing.Callable[[dict], typing.Any] = None,
    ) -> str:
        """
        Run a bash command-line or script safely in a gVisor sandbox.

        :param bash_command: Bash command or script to run.

        :return: A JSON object with the following fields: `status`, `output`. In most cases, when `status` is "OK", the user is interested in the content of the `output` field. Otherwise, report the `status` field first.
        """
        return await _run_code(
            language=Sandbox.LANGUAGE_BASH,
            code=bash_command,
            valves=self.valves,
            debug=self._debug,
            event_emitter=__event_emitter__,
        )

    async def run_python_code(
        self,
        python_code: str,
        __event_emitter__: typing.Callable[[dict], typing.Any] = None,
    ) -> str:
        """
        Run Python code safely in a gVisor sandbox.

        :param python_code: Python code to run.

        :return: A JSON object with the following fields: `status`, `output`. In most cases, when `status` is "OK", the user is interested in the content of the `output` field. Otherwise, report the `status` field first.
        """
        return await _run_code(
            language=Sandbox.LANGUAGE_PYTHON,
            code=python_code,
            valves=self.valves,
            debug=self._debug,
            event_emitter=__event_emitter__,
        )


class Sandbox:
    """
    Sandbox manages a gVisor sandbox's lifecycle.
    """

    # Set of supported programming langauges.
    LANGUAGE_PYTHON = "python"
    LANGUAGE_BASH = "bash"
    SUPPORTED_LANGUAGES = [LANGUAGE_PYTHON, LANGUAGE_BASH]

    # The following directories will be exposed as read-only to the
    # sandboxed environment. This must contain at least the necessary
    # files and libraries necessary to run the code interpreter.
    # Subdirectories of these directories may be hidden by adding them
    # to the `EMPTY_READ_ONLY_DIRECTORIES` or `EMPTY_WRITABLE_DIRECTORIES`
    # lists below.
    EXPOSED_SYSTEM_DIRECTORIES = [
        "/bin",
        "/etc/alternatives",
        "/etc/ssl/certs",
        "/lib",
        "/lib32",
        "/lib64",
        "/opt",
        "/sbin",
        "/usr",
        "/var/lib",
    ]

    # The following files will be exposed as read-only to the sandboxed
    # environment. This should contain the set of files necessary by the
    # code interpreter to function correctly, e.g. `/etc/resolv.conf`
    # is necessary to properly resolve hosts through DNS.
    EXPOSED_SYSTEM_FILES = [
        "/etc/hosts",
        "/etc/localtime",
        "/etc/mime.types",
        "/etc/nsswitch.conf",
        "/etc/os-release",
        "/etc/resolv.conf",
        "/etc/shells",
    ]

    # The following directories will exist in the sandbox environment but
    # will appear as empty and read-only.
    # This is useful to have a filesystem that feels like a normal Linux
    # environment without actually revealing these directories to the
    # sandbox.
    EMPTY_READ_ONLY_DIRECTORIES = [
        "/etc",
        "/home",
        "/lost+found",
        "/root",
        "/run",
        "/run/user",
        "/sys",
        "/var",
    ]

    # The following directories will exist in the sandbox environment but
    # will appear as empty and writable.
    # This is useful to have a filesystem that feels like a normal Linux
    # environment without actually revealing these directories to the
    # sandbox.
    EMPTY_WRITABLE_DIRECTORIES = [
        "/dev/shm",
        "/home/user",
        "/run/user/1000",
        "/var/run",
        "/var/tmp",
        "/tmp",
    ]

    # Static parts of the OCI configuration.
    OCI_CONFIG_SKELETON = {
        "ociVersion": "1.0.0",
        "process": {
            "user": {"uid": 1000, "gid": 1000},
            "args": ["/bin/INVALID"],  # Will be filled in.
            "env": [
                # Basic environment variables.
                "EDITOR=cat",
                "LANG=C.UTF-8",
                "LC_ALL=C.UTF-8",
                "LC_CTYPE=C.UTF-8",
                "HOME=/home/user",
                "HOSTNAME=sandbox",
                "PAGER=cat",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "PWD=/home/user",
                "SHLVL=1",
                "TERM=xterm",
                "USER=user",
            ],
            "cwd": "/home/user",
            "capabilities": {
                # No capabilities whatsoever.
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
            },
            "rlimits": [
                {"type": "RLIMIT_NOFILE", "hard": 1048576, "soft": 1048576},
            ],
            "noNewPrivileges": True,
        },
        "root": {
            "path": "/invalid",  # Will be filled in.
            "readonly": True,
        },
        "hostname": "sandbox",
        "mounts": [
            {"destination": "/dev", "type": "dev"},
            {"destination": "/proc", "type": "proc"},
        ],
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "mount"},
            ],
            "resources": {
                "memory": {
                    # `limit` may be be filled in here depending on user configuration.
                    "disableOOMKiller": False,
                },
            },
        },
    }

    # The path where the `runsc` binary will be downloaded and installed if
    # requested.
    AUTO_INSTALLATION_PATH = "/tmp/gvisor/runsc"

    class PlatformNotSupportedException(Exception):
        """
        Raised when the sandbox cannot run on the current platform.
        The only way to fix this is to run on a different platform.
        """

    class SandboxRuntimeException(Exception):
        """
        Raised when the sandbox fails to run properly.
        This means gVisor itself is failing, not the code in the sandbox.
        """

    class CodeExecutionError(subprocess.CalledProcessError):
        """
        Raised when the sandboxed code fails to run.
        This means the sandbox worked, but the code that ran within failed.
        """

        def __init__(self, code, **kwargs):
            super().__init__(**kwargs)
            self._code = code

        def __str__(self):
            super_str = super().__str__()
            full_code = self._code
            short_code = full_code.replace("\n", ";")
            if len(short_code) >= 128:
                short_code = short_code[:60] + "…" + short_code[-60:]
            if self.stderr:
                lines = [l.strip() for l in self.stderr.split("\n") if l.strip()]
                if len(lines) >= 2:
                    first_line, last_line = lines[0], lines[-1]
                    return f"{first_line} […] {last_line} (`{short_code}`)\n{super_str}\n```\n{full_code}\n```"
                if len(lines) == 1:
                    first_line = lines[0]
                    return f"{first_line} (`{short_code}`)\n{super_str}\n```\n{full_code}\n```"
            return f"`{short_code}` failed\n{super_str}\n```\n{full_code}\n```"

    class FixableException(Exception):
        """
        Base class for exceptions which can be addressed by the user.
        """

    class GVisorNotInstalledException(FixableException):
        """
        Raised when gVisor is not installed (`runsc` not found in $PATH).
        """

    class CorruptDownloadException(FixableException):
        """
        Raised when auto-downloading gVisor resulted in a hash mismatch.
        """

    class EnvironmentNeedsSetupException(FixableException):
        """
        Raised when the environment does not give adequate control over the
        system to run gVisor properly.
        """

    @classmethod
    def check_platform(cls):
        """
        Verifies that this tool is running on a supported platform.

        :return: Nothing.
        :raises PlatformNotSupportedException: If running on an unsupported platform.
        """
        uname = platform.uname()
        if uname.system != "Linux":
            raise cls.PlatformNotSupportedException(f"{uname.system} is not supported")
        if uname.machine not in ("x86_64", "aarch64"):
            raise cls.PlatformNotSupportedException(f"{uname.machine} is not supported")

    @classmethod
    def check_cgroups(cls):
        """
        Verifies that cgroupfs is mounted and usable for resource limit enforcement.

        :return: Nothing.
        :raises EnvironmentNeedsSetupException: If cgroupfs is not mounted or unusable for resource limit enforcement.
        """
        if not os.path.exists("/sys/fs/cgroup"):
            raise cls.EnvironmentNeedsSetupException(
                "cgroupfs not mounted as /sys/fs/cgroup but necessary for the sandbox to enforce memory limits; please mount it (`--cgroupns=host --mount=type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup,readonly=false`) or disable resource limiting"
            )
        if not os.path.exists("/sys/fs/cgroup/cgroup.subtree_control"):
            raise cls.EnvironmentNeedsSetupException(
                "/sys/fs/cgroup/cgroup.subtree_control not found; make sure you are using cgroups v2 or disable resource limiting"
            )
        # Try to open the file for writing to see if we can actually control cgroups.
        # They may be mounted read-only, as is default with Docker.
        try:
            with open(
                "/sys/fs/cgroup/cgroup.subtree_control", "wb"
            ) as subtree_control_f:
                pass
        except OSError:
            if os.getuid() != 0:
                raise cls.EnvironmentNeedsSetupException(
                    "This script is not running as root, but it needs to do so in order to enforce resource limits; please run as root or disable resource limiting"
                )
            raise cls.EnvironmentNeedsSetupException(
                "cgroupfs is not mounted writable but necessary for the sandbox to enforce memory limits; please remount it as writable (`--cgroupns=host --mount=type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup,readonly=false`) or disable resource limiting"
            )

    @classmethod
    def cgroups_available(cls) -> bool:
        """
        Returns whether cgroupfs is mounted and usable for resource limit enforcement.

        :return: Whether cgroupfs is mounted and usable for resource limit enforcement.
        """
        try:
            cls.check_cgroups()
        except:
            return False
        else:
            return True

    @classmethod
    def check_unshare(cls):
        """
        Verifies that the `unshare(2)` system call is available.

        :return: Nothing.
        :raises EnvironmentNeedsSetupException: If `unshare(2)` is not available.
        """
        if "unshare" not in os.__dict__:
            # `os.unshare` is only available in Python 3.12, which has not
            # been released to all Linux distributions yet. If unavailable,
            # try with the `unshare` command-line tool which is installed by
            # default in the OpenWebUI Docker image.
            unshare_path = shutil.which("unshare")
            if unshare_path is None:
                raise cls.EnvironmentNeedsSetupException(
                    "cannot check if the `unshare(2)` system call is available; please upgrade to Python >= 3.12 or install the `unshare` command-line tool"
                )
            try:
                subprocess.run(
                    [unshare_path, "true"], capture_output=True, timeout=3, check=True
                )
            except:
                raise cls.EnvironmentNeedsSetupException(
                    "`unshare(2)` syscall is unavailable but necessary for the sandbox to isolate itself; please remove the seccomp filter (`--security-opt=seccomp=unconfined`)"
                )
        else:
            try:
                os.unshare(0)
            except OSError:
                raise cls.EnvironmentNeedsSetupException(
                    "`unshare(2)` syscall is unavailable but necessary for the sandbox to isolate itself; please remove the seccomp filter (`--security-opt=seccomp=unconfined`)"
                )

    @classmethod
    def get_runsc_path(cls):
        """
        Returns the absolute path where the `runsc` binary is installed.

        :return: Absolute path to `runsc` binary, or `None` if not installed.
        """
        runsc_path = shutil.which("runsc")
        if runsc_path:
            return runsc_path
        if os.path.exists(cls.AUTO_INSTALLATION_PATH):
            return cls.AUTO_INSTALLATION_PATH
        return None

    @classmethod
    def runsc_needs_installation(cls):
        """
        Checks whether the `runsc` binary is installed.

        :return: Whether the `runsc` binary is installed.
        """
        return cls.get_runsc_path() is None

    @classmethod
    def install_runsc(cls):
        """
        Download and install the `runsc` binary if not already present.

        :return: Nothing.
        :raises CorruptDownloadException: If the download resulted in a hash mismatch.
        """
        if not cls.runsc_needs_installation():
            return
        uname = platform.uname()
        release_url_dir = f"https://storage.googleapis.com/gvisor/releases/release/latest/{uname.machine}"
        os.makedirs(
            os.path.dirname(cls.AUTO_INSTALLATION_PATH), mode=0o755, exist_ok=True
        )
        with tempfile.TemporaryDirectory(
            prefix="sandbox_download_"
        ) as download_tmp_dir:
            download_path = os.path.join(download_tmp_dir, "runsc")
            urllib.request.urlretrieve(
                url=f"{release_url_dir}/runsc",
                filename=download_path,
            )
            sha512_raw = urllib.request.urlopen(
                f"{release_url_dir}/runsc.sha512"
            ).read()
            want_sha512 = sha512_raw.decode("ascii").split(" ")[0]
            runsc_hash = hashlib.sha512()
            with open(download_path, "rb") as runsc_f:
                while True:
                    chunk = runsc_f.read(65536)
                    if not chunk:
                        break
                    runsc_hash.update(chunk)
            runsc_sha512 = runsc_hash.hexdigest()
            if runsc_sha512 != want_sha512:
                raise cls.CorruptDownloadException(
                    "gVisor hash mismatch when auto-installing; please install gVisor manually"
                )
            os.chmod(download_path, mode=0o755)
            os.rename(download_path, cls.AUTO_INSTALLATION_PATH)

    @classmethod
    def check_setup(
        cls, language: str, need_resource_enforcement: bool, auto_install_allowed: bool
    ):
        """
        Verifies that the environment is compatible with running sandboxes.

        :param language: The programming language to run.
        :param need_resource_enforcement: Whether the sandbox will need to enforce resource limits.
        :param auto_install_allowed: Whether auto-installation of `runsc` is allowed.

        :return: Nothing.
        :raises ValueError: If provided an invalid language name.
        :raises PlatformNotSupportedException: If running on an unsupported platform.
        :raises FixableException: If another issue occurs but that can be fixed by the user.
        """
        if language not in cls.SUPPORTED_LANGUAGES:
            raise ValueError(f"Unsupported language: {language}")
        if shutil.which("bash") is None:
            raise cls.EnvironmentNeedsSetupException(
                "bash is not installed (`bash` binary not found in $PATH); please install it"
            )
        if shutil.which("unshare") is None:
            raise cls.EnvironmentNeedsSetupException(
                "unshare is not installed (`unshare` binary not found in $PATH); please install it"
            )
        cls.check_platform()
        cls.check_unshare()
        if need_resource_enforcement:
            cls.check_cgroups()
        if not auto_install_allowed and cls.get_runsc_path() is None:
            raise cls.GVisorNotInstalledException(
                "gVisor is not installed (runsc binary not found in $PATH); please install it or enable AUTO_INSTALL valve for auto installation"
            )

    def __init__(
        self,
        tmp_dir: str,
        language: str,
        code: str,
        debug: bool,
        networking_allowed: bool,
        max_command_runtime_seconds: int,
        max_command_ram_bytes: typing.Optional[int],
    ):
        """
        Constructor.

        :param tmp_dir: Temporary directory exclusive to this sandbox. Must outlive the Sandbox object.
        :param language: The language of the code; must be one of `SUPPORTED_LANGUAGES`.
        :param code: Arbitrary code that needs to run in the sandbox.
        :param debug: Whether or not to enable debug-level logging for the sandbox.
        :param networking_allowed: Whether the code should be given access to the network.
        :param max_command_runtime_seconds: How long the code should be allowed to run, in seconds.
        :param max_command_ram_bytes: How many bytes of RAM the interpreter should be allowed to use, or `None` for no limit.
        """
        self._tmp_dir = tmp_dir
        self._language = language
        self._code = code
        self._debug = debug
        self._networking_allowed = networking_allowed
        self._max_command_runtime_seconds = max_command_runtime_seconds
        self._max_command_ram_bytes = max_command_ram_bytes
        self._sandboxed_command = None

    def setup_sandbox(self):
        """
        Set up the sandbox's root filesystem and OCI config prior to execution.
        """
        # Set up basic configuration options.
        oci_config = copy.deepcopy(self.OCI_CONFIG_SKELETON)
        if self._max_command_ram_bytes:
            oci_config["linux"]["resources"]["memory"][
                "limit"
            ] = self._max_command_ram_bytes
        self._bundle_path = os.path.join(self._tmp_dir, "bundle")
        os.makedirs(self._bundle_path, mode=0o711)
        self._runtime_root_path = os.path.join(self._tmp_dir, "runtime")
        os.makedirs(self._runtime_root_path, mode=0o711)
        self._logs_path = os.path.join(self._tmp_dir, "logs")
        os.makedirs(self._logs_path, mode=0o711)
        self._sandbox_shared_path = os.path.join(self._tmp_dir, "sandbox")
        os.makedirs(self._sandbox_shared_path, mode=0o777)
        os.chmod(self._sandbox_shared_path, mode=0o777, follow_symlinks=False)
        rootfs_path = os.path.join(self._tmp_dir, "rootfs")
        os.makedirs(rootfs_path, mode=0o755)
        oci_config["root"]["path"] = rootfs_path

        # Locate the interpreter to use.
        interpreter_path = sys.executable
        if self._language == self.LANGUAGE_BASH:
            interpreter_path = shutil.which("bash")
        if interpreter_path is None:
            raise RuntimeError("Interpreter not found")
        oci_config["mounts"].append(
            {
                "type": "bind",
                "source": interpreter_path,
                "destination": interpreter_path,
                "options": ["ro"],
            }
        )

        # Populate rootfs. This is a multi-step process.

        # Create writable empty directories.
        for d in self.EMPTY_WRITABLE_DIRECTORIES:
            rootfs_subdir = os.path.join(rootfs_path, d.removeprefix(os.path.sep))
            os.makedirs(rootfs_subdir, mode=0o755, exist_ok=True)
            oci_config["mounts"].append(
                {
                    "type": "tmpfs",
                    "destination": d,
                    "options": [],
                }
            )

        # Create read-only empty directories.
        for d in self.EMPTY_READ_ONLY_DIRECTORIES + [os.path.dirname(interpreter_path)]:
            rootfs_subdir = os.path.join(rootfs_path, d.removeprefix(os.path.sep))
            os.makedirs(rootfs_subdir, mode=0o755, exist_ok=True)

        # Handle exposed host symlinks. These will show up as symlinks with the same
        # target path in the sandbox, so they do not expose the host's view of the
        # directory they point to.
        symlinks = set()
        for l in self.EXPOSED_SYSTEM_DIRECTORIES + self.EXPOSED_SYSTEM_FILES:
            if not os.path.islink(l):
                continue
            rootfs_subpath = os.path.join(rootfs_path, l.removeprefix(os.path.sep))
            os.makedirs(os.path.dirname(rootfs_subpath), mode=0o755, exist_ok=True)
            os.symlink(src=os.readlink(l), dst=rootfs_subpath)
            symlinks.add(l)

        # Handle exposed host directories.
        for d in self.EXPOSED_SYSTEM_DIRECTORIES:
            if d in symlinks:
                continue  # It is a symlink, so already handled.
            if not os.path.isdir(d):
                continue  # The host does not have a directory at this path.
            rootfs_subdir = os.path.join(rootfs_path, d.removeprefix(os.path.sep))
            os.makedirs(rootfs_subdir, mode=0o755, exist_ok=True)
            oci_config["mounts"].append(
                {
                    "type": "bind",
                    "source": d,
                    "destination": d,
                    "options": ["ro", "rbind"],
                }
            )

        # Handle exposed host files.
        for f in self.EXPOSED_SYSTEM_FILES:
            if f in symlinks:
                continue  # It is a symlink, so already handled.
            if not os.path.isfile(f):
                continue  # The host does not have a file at this path.
            rootfs_subpath = os.path.join(rootfs_path, f.removeprefix(os.path.sep))
            rootfs_subdir = os.path.dirname(rootfs_subpath)
            os.makedirs(rootfs_subdir, mode=0o755, exist_ok=True)
            oci_config["mounts"].append(
                {
                    "type": "bind",
                    "source": f,
                    "destination": f,
                    "options": ["ro"],
                }
            )

        # Shared sandbox directory to propagate exit code.
        oci_config["mounts"].append(
            {
                "type": "bind",
                "source": self._sandbox_shared_path,
                "destination": "/sandbox",
                "options": ["rw"],
            }
        )

        # Sort mounts to ensure proper overlay order.
        oci_config["mounts"].sort(key=lambda m: m["destination"])

        # Generate some /etc files that look normal.
        with open(os.path.join(rootfs_path, "etc/hostname"), "w") as hostname_f:
            hostname_f.write("sandbox\n")
        with open(os.path.join(rootfs_path, "etc/passwd"), "w") as passwd_f:
            passwd_f.write("user:x:1000:1000:user:/home/user:/bin/bash\n")

        # Generate command line to run in the sandbox.
        self._sandboxed_command = [
            shutil.which("bash"),
            "-c",
            f'echo OK > /sandbox/started; {interpreter_path} /dev/stdin; echo "$?" > /sandbox/exit_code && exit 0',
        ]

        # Work around issue that gVisor does not preserve correct UID mappings when running as non-root user in the sandbox.
        # So map current user to 0:0, then create a new userns immediately before running command and remap to correct UID/GID.
        oci_config["process"]["user"]["uid"] = 0
        oci_config["process"]["user"]["gid"] = 0
        oci_config["process"]["args"] = [
            shutil.which("unshare"),
            "--map-user=1000",
            "--map-group=1000",
        ] + self._sandboxed_command

        # We are done. Write OCI config to bundle directory.
        with open(os.path.join(self._bundle_path, "config.json"), "w") as bundle_f:
            json.dump(oci_config, bundle_f, indent=2, sort_keys=True)

    def run(self) -> subprocess.CompletedProcess:
        """
        Spawn and wait for the sandbox.

        :return: A `CompletedProcess` object representing the return code and stdout/stderr of the code interpreter.
        :raises Sandbox.SandboxRuntimeException: If the sandbox failed to start or behaved incorrectly regardless of the code being evaluated.
        :raises subprocess.TimeoutExpired: If the code interpreter ran for longer than configured.
        :raises sandbox.CodeExecutionError: If the code interpreter failed to execute the given code. This does not represent a sandbox failure.
        """
        network_mode = "host" if self._networking_allowed else "none"
        ignore_cgroups_mode = "false" if self.cgroups_available() else "true"
        debug_mode = "true" if self._debug else "false"
        runsc_argv = [
            self.get_runsc_path(),
            "--rootless=true",
            "--directfs=false",
            f"--network={network_mode}",
            f"--ignore-cgroups={ignore_cgroups_mode}",
            f"--root={self._runtime_root_path}",
            f"--debug={debug_mode}",
            f"--debug-log={self._logs_path}/",
            "run",
            f"--bundle={self._bundle_path}",
            "sandbox",
        ]
        started_marker_path = os.path.join(self._sandbox_shared_path, "started")
        try:
            result = subprocess.run(
                runsc_argv,
                input=self._code + "\n",
                text=True,
                capture_output=True,
                timeout=self._max_command_runtime_seconds,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            if os.path.isfile(started_marker_path):
                raise e
            errors = collections.defaultdict(list)

            def process_log(filename, log_line):
                if log_line and log_line[0] in "WEF":  # [W]arning, [E]rror, [F]atal
                    errors[filename].append(log_line)

            self.debug_logs(process_log)
            stderr = e.stderr.strip()
            raise self.SandboxRuntimeException(
                f"Sandbox failed to start: {e}; stderr: {stderr}; logs: {errors}"
            )
        if not os.path.isfile(started_marker_path):
            raise self.SandboxRuntimeException(f"Sandbox failed to start up properly")
        exit_code_path = os.path.join(self._sandbox_shared_path, "exit_code")
        if not os.path.isfile(exit_code_path):
            raise self.SandboxRuntimeException("Sandbox failed to record an exit code")
        with open(exit_code_path, "r") as exit_code_f:
            exit_code_str = exit_code_f.read()
        try:
            exit_code = int(exit_code_str.strip())
        except ValueError as e:
            raise self.SandboxRuntimeException(
                f"Sandbox recorded non-integer exit code: {e}"
            )
        if exit_code != 0:
            raise self.CodeExecutionError(
                code=self._code,
                returncode=exit_code,
                cmd=self._sandboxed_command,
                output=result.stdout,
                stderr=result.stderr,
            )
        return result

    def debug_logs(self, write_fn: typing.Callable[[str, str], typing.Any]):
        """
        Write debug logs to the given function.

        May only be called after `run` returns, but may be called even when
        `run` fails.

        :param write_fn: A function that takes (filename, log line) as arguments.
        """
        all_logs = []
        for log_filename in os.listdir(self._logs_path):
            if not log_filename.endswith(".txt"):
                continue
            log_path = os.path.join(self._logs_path, log_filename)
            with open(log_path, "r") as log_f:
                for log_line in log_f:
                    log_line = log_line.rstrip()
                    if not log_line:
                        continue
                    all_logs.append((log_filename, log_line))
        for filename, log_entry in all_logs:
            write_fn(filename, log_entry)


class EventEmitter:
    """
    Helper wrapper for event emissions.
    """

    def __init__(
        self,
        event_emitter: typing.Callable[[dict], typing.Any] = None,
        debug: bool = False,
    ):
        self.event_emitter = event_emitter
        self._debug = debug

    async def _emit(self, typ, data):
        if self._debug:
            print(f"Emitting {typ} event: {data}", file=sys.stderr)
        if not self.event_emitter:
            return None
        maybe_future = self.event_emitter(
            {
                "type": typ,
                "data": data,
            }
        )
        if asyncio.isfuture(maybe_future) or inspect.isawaitable(maybe_future):
            return await maybe_future

    async def status(
        self, description="Unknown state", status="in_progress", done=False
    ):
        await self._emit(
            "status",
            {
                "status": status,
                "description": description,
                "done": done,
            },
        )

    async def fail(self, description="Unknown error"):
        await self.status(description=description, status="error", done=True)


async def _run_code(
    language: str,
    code: str,
    valves: Tools.Valves,
    debug: bool,
    event_emitter: typing.Callable[[dict], typing.Any] = None,
) -> str:
    """
    Run code safely in a gVisor sandbox.

    :param language: Programming language of the code.
    :param code: The code to run.
    :param valves: The valves set on the tool.
    :param debug: Whether to print debug logs after the sandbox runs.
    :param event_emitter: Event emitter to send status updates to.

    :return: A JSON object with the following fields: `status`, `output`. In most cases, when `status` is "OK", the user is interested in the content of the `output` field. Otherwise, report the `status` field first.
    """
    emitter = EventEmitter(event_emitter, debug=debug)

    async def _fail(error_message):
        await emitter.fail(error_message)
        return json.dumps({"status": "ERROR", "output": error_message})

    try:
        max_command_ram_bytes = None
        if valves.MAX_COMMAND_RAM_MEGABYTES != 0:
            max_command_ram_bytes = valves.MAX_COMMAND_RAM_MEGABYTES * 1024 * 1024

        await emitter.status("Checking if environment supports sandboxing...")
        Sandbox.check_setup(
            language=language,
            need_resource_enforcement=max_command_ram_bytes is not None,
            auto_install_allowed=valves.AUTO_INSTALL,
        )

        if valves.AUTO_INSTALL and Sandbox.runsc_needs_installation():
            await emitter.status("Auto-installing gVisor...")
            Sandbox.install_runsc()

        await emitter.status("Initializing sandbox configuration...")
        status = "UNKNOWN"
        output = None
        language_title = language.title()

        # If the provided code starts/ends with "```" or
        # "```SOME_LANGUAGE", remove that.
        code = code.strip()
        code = code.removeprefix("```" + language)
        code = code.removeprefix("```")
        code = code.removesuffix("```")

        # If the provided code is a single line enclosed in
        # "`"s, strip those and whitespace away.
        code = code.strip()
        code = code.strip("`")
        code = code.strip()

        with tempfile.TemporaryDirectory(prefix="sandbox_") as tmp_dir:
            sandbox = Sandbox(
                tmp_dir=tmp_dir,
                language=language,
                code=code,
                debug=debug,
                networking_allowed=valves.NETWORKING_ALLOWED,
                max_command_runtime_seconds=valves.MAX_COMMAND_RUNTIME_SECONDS,
                max_command_ram_bytes=max_command_ram_bytes,
            )

            await emitter.status("Setting up sandbox environment...")
            sandbox.setup_sandbox()

            await emitter.status(f"Running {language_title} code in gVisor sandbox...")
            try:
                result = sandbox.run()
            except subprocess.TimeoutExpired as e:
                await emitter.fail(
                    f"Code timed out after {valves.MAX_COMMAND_RUNTIME_SECONDS} seconds"
                )
                status = "TIMEOUT"
                output = e.stderr
            except subprocess.CalledProcessError as e:
                await emitter.fail(f"{language_title}: {e}")
                status = "ERROR"
                output = e.stderr
            else:
                await emitter.status(
                    status="complete",
                    done=True,
                    description=f"{language_title} code executed successfully.",
                )
                status = "OK"
                output = result.stdout or result.stderr
            if output:
                output = output.strip()
            if debug:

                def _log(filename: str, log_line: str):
                    print(f"[{filename}] {log_line}", file=sys.stderr)

                sandbox.debug_logs(_log)
        return json.dumps(
            {
                "status": status,
                "output": output,
            },
            ensure_ascii=False,
        )
    except Sandbox.PlatformNotSupportedException as e:
        return await _fail(f"Sandbox cannot run on this machine: {e}")
    except Sandbox.SandboxRuntimeException as e:
        return await _fail(f"Sandbox runtime failed: {e}")
    except Sandbox.FixableException as e:
        return await _fail(f"Environment needs setup work: {e}")
    except Exception as e:
        return await _fail(f"Unhandled exception: {e}")


# Debug utility: Run code from stdin if running as a normal Python script.
if __name__ == "__main__":
    is_debug = "--debug" in sys.argv[1:]
    is_bash = "--bash" in sys.argv[1:]
    if "--use-sample-code" in sys.argv[1:]:
        if is_bash:
            sample_instructions = (
                "echo 'Hello from the sandbox!'",
                "date",
                "dmesg",
                "echo 'Bye from the sandbox!'",
            )
        else:
            sample_instructions = (
                "print('Hello from the sandbox!')",
                "import datetime, sys",
                "print('Current date and time:', datetime.datetime.now())",
                "sys.stdout.flush()",
                "import shutil, subprocess",
                "subprocess.run([shutil.which('dmesg')], check=True)",
                "print('Bye from the sandbox!')",
            )
            code = ";\n".join(sample_instructions) + "\n"
    else:
        code = sys.stdin.read()

    async def _local_run():
        def _dummy_emitter(event):
            print(f"Event: {event}", file=sys.stderr)

        tools = Tools()
        tools._debug = is_debug
        if is_bash:
            output = await tools.run_bash_command(
                bash_command=code, __event_emitter__=_dummy_emitter
            )
        else:
            output = await tools.run_python_code(
                python_code=code, __event_emitter__=_dummy_emitter
            )
        print(output, file=sys.stderr)

    asyncio.run(_local_run())
