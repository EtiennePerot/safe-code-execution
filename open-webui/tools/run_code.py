"""
id: run_code
title: Run code
description: Run arbitrary Python or Bash code safely in a gVisor sandbox.
author: EtiennePerot
author_url: https://github.com/EtiennePerot/safe-code-execution
funding_url: https://github.com/EtiennePerot/safe-code-execution
version: 0.8.0
license: Apache-2.0
"""


# NOTE: If running Open WebUI in a container, you *need* to set up this container to allow sandboxed code execution.
# Please read the docs here:
#
#   https://github.com/EtiennePerot/safe-code-execution/blob/master/README.md
#
# This is an OpenWebUI *tool*. It allows an LLM to generate and call code on its own.
# If you are looking for an OpenWebUI *function* to allow you to manually execute blocks
# of code in the LLM output, see here instead:
# https://openwebui.com/f/etienneperot/run_code/

#
# See https://github.com/EtiennePerot/safe-code-execution for more info.
#
# Protip: You can test this manually by running it as a Python script, like so:
# (Run this inside the Open WebUI container)
#
#   python3 run_code.py --self_test
#
# This will simulate that OpenWebUI would do if it asked this tool to evaluate the Python code `print("Hello world!")`.
# This can be useful when setting up this tool to verify that it works in your environment.
# You can also use it for one-off code execution like this:
#
#   echo 'print("Hello world!")' | python3 run_code.py
#

import asyncio
import argparse
import json
import os
import os.path
import pydantic
import subprocess
import sys
import tempfile
import typing
import inspect
import uuid
import base64
import ctypes
import ctypes.util
import copy
import hashlib
import platform
import re
import shutil
import signal
import threading
import time
import urllib.request
import datetime
import urllib.error


class _Tools:
    class Valves(pydantic.BaseModel):
        _VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX = "CODE_EVAL_VALVE_OVERRIDE_"
        NETWORKING_ALLOWED: bool = pydantic.Field(
            default=True,
            description=f"Whether to allow network access during code execution; may be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}NETWORKING_ALLOWED.",
        )
        MAX_RUNTIME_SECONDS: int = pydantic.Field(
            ge=1,
            default=30,
            description=f"Maximum number of seconds code is given to run; may be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}MAX_RUNTIME_SECONDS.",
        )
        MAX_RAM_MEGABYTES: int = pydantic.Field(
            ge=0,
            default=128,
            description=f"Maximum number of megabytes that the interpreter has when running. Must run as root with host cgroups writable (`--mount=type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup,readonly=false`) for this to work. Set to 0 to disable memory limits. May be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}MAX_RAM_MEGABYTES",
        )
        REQUIRE_RESOURCE_LIMITING: bool = pydantic.Field(
            default=True,
            description=f"Whether to enforce resource limiting, which requires cgroups v2 to be available; may be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}REQUIRE_RESOURCE_LIMITING.",
        )
        AUTO_INSTALL: bool = pydantic.Field(
            default=True,
            description=f"Whether to automatically install gVisor if not installed on the system; may be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}AUTO_INSTALL. Use the 'HTTPS_PROXY' environment variable to control the proxy used for download.",
        )
        CHECK_FOR_UPDATES: bool = pydantic.Field(
            default=True,
            description=f"Whether to automatically check for updates; may be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}CHECK_FOR_UPDATES. Use the 'HTTPS_PROXY' environment variable to control the proxy used for update checks.",
        )
        DEBUG: bool = pydantic.Field(
            default=False,
            description=f"Whether to produce debug logs during execution; may be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}DEBUG.",
        )

    def __init__(self, valves):
        self.valves = valves
        for valve_name, valve_value in valves.dict().items():
            override = os.getenv(
                self.valves._VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX
                + valve_name
            )
            if override is None:
                continue
            try:
                if type(valve_value) is type(True):
                    assert override.lower() in (
                        "true",
                        "false",
                    ), 'Value must be "true" or "false"'
                    override = override.lower() == "true"
                elif type(valve_value) is type(42):
                    override = int(override)
                else:
                    valve_value_type = type(valve_value)
                    raise ValueError(f"Unknown valve type: {valve_value_type}")
            except Exception as e:
                raise ValueError(
                    f"Valve override {self.valves._VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}{valve_name}={valve_value}: bad value: {e}"
                )
            else:
                setattr(self.valves, valve_name, override)

    async def run_bash_command(
        self,
        bash_command: str,
        __event_emitter__: typing.Callable[[dict], typing.Any] = None,
    ) -> str:
        """
        Run a bash command-line or script safely in a gVisor sandbox.

        :param bash_command: Bash command or script to run.

        :return: A JSON object with the following fields: `bash_command`, `status`, `output`. In most cases, when `status` is "OK", the user is interested in the content of the `output` field. Otherwise, report the `status` field first.
        """
        result = await self._run_code(
            language=Sandbox.LANGUAGE_BASH,
            code=bash_command,
            event_emitter=__event_emitter__,
        )
        return json.dumps(
            {
                "bash_command": bash_command,
                "status": result["status"],
                "output": result["output"],
            },
            ensure_ascii=False,
        )

    async def run_python_code(
        self,
        python_code: str,
        __event_emitter__: typing.Callable[[dict], typing.Any] = None,
    ) -> str:
        """
        Run Python code safely in a gVisor sandbox.

        :param python_code: Python code to run.

        :return: A JSON object with the following fields: `python_code`, `status`, `output`. In most cases, when `status` is "OK", the user is interested in the content of the `output` field. Otherwise, report the `status` field first.
        """
        result = await self._run_code(
            language=Sandbox.LANGUAGE_PYTHON,
            code=python_code,
            event_emitter=__event_emitter__,
        )
        return json.dumps(
            {
                "python_code": python_code,
                "status": result["status"],
                "output": result["output"],
            },
            ensure_ascii=False,
        )

    async def _run_code(
        self,
        language: str,
        code: str,
        event_emitter: typing.Callable[[dict], typing.Any] = None,
    ) -> str:
        """
        Run code safely in a gVisor sandbox.

        :param language: Programming language of the code.
        :param code: The code to run.
        :param event_emitter: Event emitter to send status updates to.

        :return: A dictionary with the following fields: `status`, `output`.
        """
        valves = self.valves
        debug = valves.DEBUG
        emitter = EventEmitter(event_emitter, debug=debug)
        execution_tracker: typing.Optional[CodeExecutionTracker] = None

        if valves.CHECK_FOR_UPDATES:
            if UpdateCheck.need_check():
                await emitter.status("Checking for updates...")
            try:
                newer_version = UpdateCheck.get_newer_version()
            except UpdateCheck.VersionCheckError as e:
                emitter.set_status_prefix(f"[Code execution update check failed: {e}] ")
            else:
                if newer_version is not None:
                    await emitter.status(
                        f"Code execution: Update available: {newer_version}"
                    )
                    emitter.set_status_prefix(
                        f"[Code execution update available: {newer_version}] "
                    )

        async def _fail(error_message, status="SANDBOX_ERROR"):
            if execution_tracker is not None:
                execution_tracker.set_error(error_message)
                await emitter.code_execution(execution_tracker)
            if debug:
                await emitter.fail(
                    f"[DEBUG MODE] {error_message}; language={language}; code={code}; valves=[{valves}]"
                )
            else:
                await emitter.fail(error_message)
            return {"status": status, "output": error_message}

        try:
            max_ram_bytes = None
            if valves.MAX_RAM_MEGABYTES != 0:
                max_ram_bytes = valves.MAX_RAM_MEGABYTES * 1024 * 1024

            Sandbox.check_setup(
                language=language,
                auto_install_allowed=valves.AUTO_INSTALL,
                require_resource_limiting=valves.REQUIRE_RESOURCE_LIMITING,
            )

            if valves.AUTO_INSTALL and Sandbox.runsc_needs_installation():
                await emitter.status("Auto-installing gVisor...")
                Sandbox.install_runsc()

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

            execution_tracker = CodeExecutionTracker(
                name=f"{language_title} tool execution", code=code, language=language
            )
            await emitter.clear_status()
            await emitter.code_execution(execution_tracker)

            with tempfile.TemporaryDirectory(prefix="sandbox_") as tmp_dir:
                sandbox = Sandbox(
                    tmp_dir=tmp_dir,
                    snippets=((language, code),),
                    debug=debug,
                    networking_allowed=valves.NETWORKING_ALLOWED,
                    max_runtime_seconds=valves.MAX_RUNTIME_SECONDS,
                    max_ram_bytes=max_ram_bytes,
                    require_resource_limiting=valves.REQUIRE_RESOURCE_LIMITING,
                    persistent_home_dir=None,
                )

                try:
                    result = sandbox.run()
                except Sandbox.ExecutionTimeoutError as e:
                    await emitter.fail(
                        f"Code timed out after {valves.MAX_RUNTIME_SECONDS} seconds"
                    )
                    execution_tracker.set_error(
                        f"Code timed out after {valves.MAX_RUNTIME_SECONDS} seconds"
                    )
                    status = "TIMEOUT"
                    output = e.stderr
                except Sandbox.InterruptedExecutionError as e:
                    await emitter.fail("Code used too many resources")
                    execution_tracker.set_error("Code used too many resources")
                    status = "INTERRUPTED"
                    output = e.stderr
                except Sandbox.CodeExecutionError as e:
                    await emitter.fail(f"{language_title}: {e}")
                    execution_tracker.set_error(f"{language_title}: {e}")
                    status = "ERROR"
                    output = e.stderr
                else:
                    status = "OK"
                    output = result.stdout or result.stderr
                    await emitter.message(
                        f"\n<details>\n<summary>Code Execution</summary>\nI executed the following {language} code:\n```{language}\n{code}\n```\n```Output\n{output.strip()}\n```\n</details>\n"
                    )
                if output:
                    output = output.strip()
                    execution_tracker.set_output(output)
                if debug:
                    per_file_logs = {}

                    def _log(filename: str, log_line: str):
                        print(f"[{filename}] {log_line}", file=sys.stderr)
                        if filename not in per_file_logs:
                            per_file_logs[filename] = []
                        per_file_logs[filename].append(log_line)

                    sandbox.debug_logs(_log)
                    await emitter.status(
                        status="complete" if status == "OK" else "error",
                        done=True,
                        description=f"[DEBUG MODE] status={status}; output={output}; valves=[{valves}]; debug={per_file_logs}",
                    )
            await emitter.code_execution(execution_tracker)
            return {
                "status": status,
                "output": output,
            }
        except Sandbox.PlatformNotSupportedException as e:
            return await _fail(f"Sandbox cannot run on this machine: {e}")
        except Sandbox.SandboxRuntimeException as e:
            return await _fail(f"Sandbox runtime failed: {e}")
        except Sandbox.FixableException as e:
            return await _fail(f"Environment needs setup work: {e}")
        except Sandbox.SandboxException as e:
            return await _fail(f"Sandbox exception: {e}")
        except Exception as e:
            return await _fail(f"Unhandled exception: {e}")


class Tools:
    Valves = _Tools.Valves

    def __init__(self):
        self.valves = self.Valves()

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
        return await _Tools(self.valves).run_bash_command(
            bash_command=bash_command,
            __event_emitter__=__event_emitter__,
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
        return await _Tools(self.valves).run_python_code(
            python_code=python_code,
            __event_emitter__=__event_emitter__,
        )


# fmt: off


class EventEmitter:
    """
    Helper wrapper for OpenWebUI event emissions.
    """

    def __init__(
        self,
        event_emitter: typing.Callable[[dict], typing.Any] = None,
        debug: bool = False,
    ):
        self.event_emitter = event_emitter
        self._debug = debug
        self._status_prefix = None
        self._emitted_status = False

    def set_status_prefix(self, status_prefix):
        self._status_prefix = status_prefix

    async def _emit(self, typ, data, twice):
        if self._debug:
            print(f"Emitting {typ} event: {data}", file=sys.stderr)
        if not self.event_emitter:
            return None
        result = None
        for i in range(2 if twice else 1):
            maybe_future = self.event_emitter(
                {
                    "type": typ,
                    "data": data,
                }
            )
            if asyncio.isfuture(maybe_future) or inspect.isawaitable(maybe_future):
                result = await maybe_future
        return result

    async def status(
        self, description="Unknown state", status="in_progress", done=False
    ):
        self._emitted_status = True
        if self._status_prefix is not None:
            description = f"{self._status_prefix}{description}"
        await self._emit(
            "status",
            {
                "status": status,
                "description": description,
                "done": done,
            },
            twice=not done and len(description) <= 1024,
        )

    async def fail(self, description="Unknown error"):
        await self.status(description=description, status="error", done=True)

    async def clear_status(self):
        if not self._emitted_status:
            return
        self._emitted_status = False
        await self._emit(
            "status",
            {
                "status": "complete",
                "description": "",
                "done": True,
            },
            twice=True,
        )

    async def message(self, content):
        await self._emit(
            "message",
            {
                "content": content,
            },
            twice=False,
        )

    async def citation(self, document, metadata, source):
        await self._emit(
            "citation",
            {
                "document": document,
                "metadata": metadata,
                "source": source,
            },
            twice=False,
        )

    async def code_execution(self, code_execution_tracker):
        await self._emit(
            "citation", code_execution_tracker._citation_data(), twice=True
        )


class CodeExecutionTracker:
    def __init__(self, name, code, language):
        self._uuid = str(uuid.uuid4())
        self.name = name
        self.code = code
        self.language = language
        self._result = {}

    def set_error(self, error):
        self._result["error"] = error

    def set_output(self, output):
        self._result["output"] = output

    def add_file(self, name, url):
        if "files" not in self._result:
            self._result["files"] = []
        self._result["files"].append(
            {
                "name": name,
                "url": url,
            }
        )

    def _citation_data(self):
        data = {
            "type": "code_execution",
            "uuid": self._uuid,
            "name": self.name,
            "code": self.code,
            "language": self.language,
        }
        if "output" in self._result or "error" in self._result:
            data["result"] = self._result
        return data


class Sandbox:
    """
    Sandbox manages a gVisor sandbox's lifecycle.
    """

    # Set of supported programming languages.
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

    # Regular expression for log filename prefixes generated by `runsc`.
    _LOG_FILENAME_TRUNCATE_RE = re.compile(r"^runsc\.log\.\d{8}-\d{6}(?:\.\d+)?\.")

    # Other files worth logging when dumping debug logs.
    _EXTRA_DEBUG_LOG_PATHS = (
        "/etc/os-release",
        "/proc/self/cgroup",
        "/proc/self/personality",
        "/proc/self/mountinfo",
        "/proc/self/setgroups",
        "/proc/self/status",
        "/proc/self/uid_map",
        "/proc/self/gid_map",
        "/proc/cmdline",
        "/proc/cpuinfo",
        "/proc/cgroups",
        "/proc/mounts",
        "/proc/version",
    )

    # Other commands worth running when dumping debug logs.
    _EXTRA_DEBUG_LOG_COMMANDS = (
        ("pwd",),
        ("id",),
        ("uname", "-a"),
        ("ls", "-l", "/proc/self/ns"),
        ("findmnt",),
        (sys.executable, "--version"),
    )

    # Environment variable used to detect interpreter re-execution.
    _MARKER_ENVIRONMENT_VARIABLE = "__CODE_EXECUTION_STAGE"

    # Re-execution stages.
    _STAGE_SANDBOX = "SANDBOX"
    _STAGE_SNIPPET = "SNIPPET"

    # libc bindings.
    # Populated using `_libc`.
    _LIBC = None

    class _Libc:
        """
        Wrapper over libc functions.
        """

        def __init__(self):
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            libc.mount.argtypes = (ctypes.c_char_p,)
            self._libc = libc

        def mount(self, source, target, fs, options):
            if (
                self._libc.mount(
                    source.encode("ascii"),
                    target.encode("ascii"),
                    fs.encode("ascii"),
                    0,
                    options.encode("ascii"),
                )
                < 0
            ):
                errno = ctypes.get_errno()
                raise OSError(
                    errno,
                    f"mount({source}, {target}, {fs}, {options}): {os.strerror(errno)}",
                )

        def umount(self, path):
            if self._libc.umount(path.encode("ascii")) < 0:
                errno = ctypes.get_errno()
                raise OSError(errno, f"umount({path}): {os.strerror(errno)}")

        def unshare(self, flags):
            if self._libc.unshare(flags) < 0:
                raise OSError(f"unshare({flags}) failed")

    class _SelfFile:
        """
        Manages a copy of this file's own contents.
        """

        _CONTENTS = None

        @classmethod
        def init(cls):
            """
            Read `__file__` into `cls._CONTENTS`. Must be called during init.
            """
            if cls._CONTENTS is None:
                with open(__file__, "rb") as self_f:
                    cls._CONTENTS = self_f.read().decode("ascii")

        @classmethod
        def contents(cls) -> str:
            """
            Return this file's own contents.
            """
            assert cls._CONTENTS is not None, f"{cls.__name__}.init not called"
            return cls._CONTENTS

    class _Switcheroo:
        """
        Management of the switcheroo procedure for running in a usable cgroup namespace and node.
        """

        _CGROUP_ROOT = "/sys/fs/cgroup"
        _CGROUP_NAME_PREFIX = "codeeval_"
        _CGROUP_MAX_COUNT = 4096
        _CGROUP_SANDBOX_NAME = "sandbox"
        _CGROUP_SUPERVISOR_NAME = "supervisor"
        _CGROUP_LEAF = "leaf"

        def __init__(self, libc, log_path, max_sandbox_ram_bytes, do_resource_limiting):
            self._libc = libc
            self._log_path = log_path
            self._max_sandbox_ram_bytes = max_sandbox_ram_bytes
            self._do_resource_limiting = do_resource_limiting
            self._my_euid = None
            self._my_egid = None
            self._checkpoint = None
            self._cgroup_controllers = None
            self._needed_controllers = set()
            if max_sandbox_ram_bytes is not None:
                self._needed_controllers.add("memory")
            self._initial_cgroup_name = None
            self._codeeval_cgroup_name = None
            self._moved = False
            self._operations = [
                # Save EUID and EGID before we move to a new user namespace.
                ("save_euid", self._save_euid),
                ("save_egid", self._save_egid),
                ("unshare_user", self._unshare_user),
                # Map our current user as being root in the new user namespace.
                ("write_uid_map", self._write_uid_map),
                ("write_setgroups", self._write_setgroups),
                ("write_gid_map", self._write_gid_map),
            ]
            if do_resource_limiting:
                self._operations.extend(
                    (
                        # cgroupfs's view does not take into account cgroup namespaces.
                        # Weird, right?
                        # This means `/proc/PID/cgroup` will show the namespaced view of
                        # the cgroup that the PID is in, but `/sys/fs/cgroup` will still
                        # contain the whole system cgroup hierarchy regardless of namespace.
                        # Instead, namespaces act as "boundary box" around process movement
                        # requests when writing to cgroup.procs or creating new cgroups.
                        # So our first order of business here is to find out which cgroup we
                        # are running in. We do this by scanning the whole cgroupfs hierarchy
                        # and looking for our PID. This will populate
                        # `self._initial_cgroup_name`.
                        (
                            "find_self_in_cgroup_hierarchy",
                            self._find_self_in_cgroup_hierarchy,
                        ),
                        # The cgroup nesting rules are complicated, but the short of it is:
                        # A cgroup can either **contain processes** OR **have limits**.
                        # Also, cgroups that contain processes must be leaf nodes.
                        # Also, cgroups that enforce limits must have their parent cgroup
                        # also have the same limit "controller" be active.
                        # So we will have two types of cgroups:
                        #  - Leaf nodes with no controllers
                        #  - Non-leaf nodes with controllers
                        # So initially, all the processes in the container's initial
                        # namespace need to be moved out to a new leaf node,
                        # otherwise we cannot turn on controllers on the initial
                        # cgroup.
                        # So we will set up the following hierarchy:
                        #   /sys/fs/cgroup/$INITIAL:
                        #     The cgroup where the container's processes were running
                        #     the first time we run any Sandbox in the container.
                        #     It may initially have no controllers enabled, but we will
                        #     turn them on later.
                        #   /sys/fs/cgroup/$INITIAL/leaf:
                        #     The cgroup where the container's processes are moved to
                        #     from the $INITIAL cgroup upon first run of any Sandbox in
                        #     this container. When this code runs again, processes that
                        #     are already in `$INITIAL/leaf` are not moved.
                        #   /sys/fs/cgroup/$INITIAL/codeeval_$NUM:
                        #     A per-Sandbox cgroup that never contains any processes.
                        #     It will have controllers enabled on it but will never have
                        #     specific limits enforced.
                        #   /sys/fs/cgroup/$INITIAL/codeeval_$NUM/sandbox:
                        #     A per-Sandbox cgroup that never contains any processes.
                        #     It will have controllers enabled on it and will enforce
                        #     resource limits for the processes running in its /leaf.
                        #   /sys/fs/cgroup/$INITIAL/codeeval_$NUM/sandbox/leaf:
                        #     A per-Sandbox cgroup that is running `runsc` (gVisor).
                        #     It has no controllers enabled on it, but resources are
                        #     being enforced by virtue of being a child of
                        #     `$INITIAL/codeeval_$NUM/sandbox` which does enforce limits.
                        #   /sys/fs/cgroup/$INITIAL/codeeval_$NUM/supervisor:
                        #     A per-Sandbox cgroup that never contains any processes.
                        #     It will have controllers enabled on it and will enforce
                        #     resource limits for the processes running in its /leaf.
                        #   /sys/fs/cgroup/$INITIAL/codeeval_$NUM/supervisor/leaf:
                        #     A per-Sandbox cgroup that is running a Python interpreter
                        #     that manages the lifetime of the `runsc` process.
                        #     It will run `Sandbox.maybe_main`.
                        #     It has no controllers enabled on it, but resources are
                        #     being enforced by virtue of being a child of
                        #     `$INITIAL/codeeval_$NUM/sandbox` which does enforce limits.
                        #
                        # This particular step creates the `$INITIAL/leaf` cgroup.
                        # If already created, it does nothing.
                        (
                            "create_initial_leaf_cgroup",
                            self._create_initial_leaf_cgroup,
                        ),
                        # Move all processes in `$INITIAL` to `$INITIAL/leaf`.
                        (
                            "move_initial_cgroup_processes_to_initial_leaf_cgroup",
                            self._move_initial_cgroup_processes_to_initial_leaf_cgroup,
                        ),
                        # Read the cgroup controllers enabled in `$INITIAL`. This acts
                        # as a bounding set on the ones we can enable in any child of it.
                        ("read_cgroup_controllers", self._read_cgroup_controllers),
                        # Cleanup old `$INITIAL/codeeval_*` cgroups that may be lying
                        # around from past runs.
                        ("cleanup_old_cgroups", self._cleanup_old_cgroups),
                        # Create a new `$INITIAL/codeeval_$NUM` cgroup.
                        ("create_codeeval_cgroup", self._create_codeeval_cgroup),
                        # Create a new `$INITIAL/codeeval_$NUM/sandbox` cgroup.
                        ("create_sandbox_cgroup", self._create_sandbox_cgroup),
                        # Create a new `$INITIAL/codeeval_$NUM/sandbox/leaf` cgroup.
                        (
                            "create_sandbox_leaf_cgroup",
                            self._create_sandbox_leaf_cgroup,
                        ),
                        # Create a new `$INITIAL/codeeval_$NUM/supervisor` cgroup.
                        ("create_supervisor_cgroup", self._create_supervisor_cgroup),
                        # Create a new `$INITIAL/codeeval_$NUM/supervisor/leaf` cgroup.
                        (
                            "create_supervisor_leaf_cgroup",
                            self._create_supervisor_leaf_cgroup,
                        ),
                        # Add controllers to `$INITIAL`.
                        (
                            "add_cgroup_controllers_to_root",
                            self._add_cgroup_controllers_to_root,
                        ),
                        # Add controllers to `$INITIAL/codeeval_$NUM`.
                        (
                            "add_cgroup_controllers_to_codeeval",
                            self._add_cgroup_controllers_to_codeeval,
                        ),
                        # Add controllers to `$INITIAL/codeeval_$NUM/sandbox`.
                        (
                            "add_cgroup_controllers_to_sandbox",
                            self._add_cgroup_controllers_to_sandbox,
                        ),
                        # Set resource limits on `$INITIAL/codeeval_$NUM`.
                        ("set_sandbox_cgroup_limits", self._set_sandbox_cgroup_limits),
                        # Add controllers to `$INITIAL/codeeval_$NUM/supervisor`.
                        (
                            "add_cgroup_controllers_to_supervisor",
                            self._add_cgroup_controllers_to_supervisor,
                        ),
                        # Set resource limits on `$INITIAL/codeeval_$NUM/supervisor`.
                        (
                            "set_supervisor_cgroup_limits",
                            self._set_supervisor_cgroup_limits,
                        ),
                        # Move current process to
                        # `$INITIAL/codeeval_$NUM/supervisor/leaf`.
                        (
                            "move_process_to_supervisor_leaf",
                            self._move_process_to_supervisor_leaf,
                        ),
                        # Double-check that we have moved to
                        # `$INITIAL/codeeval_$NUM/supervisor/leaf`.
                        ("sanity_check_own_cgroup", self._sanity_check_own_cgroup),
                    )
                )

        def _status(self):
            """
            Return the current switcheroo status.

            :return: The last successful operation name, "UNSTARTED" if unstarted, or "OK" if all done, and some information.
            """
            main_status = self._checkpoint
            if self._checkpoint is None:
                main_status = "UNSTARTED"
            if self._checkpoint == self._operations[-1][0]:
                main_status = "OK"
            my_pid = os.getpid()
            status_line = f"{main_status} (euid={self._my_euid} egid={self._my_egid} pid={my_pid} do_resource_limiting={self._do_resource_limiting} initial_cgroup_name={self._initial_cgroup_name} codeeval_cgroup_name={self._codeeval_cgroup_name} controllers={self._cgroup_controllers})"
            want_headers = (
                "Name",
                "Umask",
                "State",
                "Uid",
                "Gid",
                "Groups",
                "NStgid",
                "NSpid",
                "NSpgid",
                "CapInh",
                "CapPrm",
                "CapEff",
                "CapBnd",
                "CapAmb",
                "NoNewPrivs",
                "Seccomp",
                "Seccomp_filters",
            )
            got_headers = {}
            try:
                with self._open("/proc/self/status", "rb") as status_f:
                    for line in status_f.read().decode("utf-8").splitlines():
                        for header in want_headers:
                            if line.startswith(f"{header}:"):
                                got_headers[header] = line.split(":")[1].strip()
                                break
            except OSError as e:
                status_line += f" (error opening /proc/self/status: {e})"
            else:
                for header in want_headers:
                    got_value = got_headers.get(header)
                    status_line += f" {header}={got_value}"
            if self._do_resource_limiting:
                cgroupfs_data = []
                for cgroup_components in (
                    (self._initial_cgroup_name,),
                    (self._initial_cgroup_name, self._CGROUP_LEAF),
                    (self._initial_cgroup_name, self._codeeval_cgroup_name),
                    (
                        self._initial_cgroup_name,
                        self._codeeval_cgroup_name,
                        self._CGROUP_LEAF,
                    ),
                    (
                        self._initial_cgroup_name,
                        self._codeeval_cgroup_name,
                        self._CGROUP_SUPERVISOR_NAME,
                    ),
                    (
                        self._initial_cgroup_name,
                        self._codeeval_cgroup_name,
                        self._CGROUP_SUPERVISOR_NAME,
                        self._CGROUP_LEAF,
                    ),
                    (
                        self._initial_cgroup_name,
                        self._codeeval_cgroup_name,
                        self._CGROUP_SANDBOX_NAME,
                    ),
                    (
                        self._initial_cgroup_name,
                        self._codeeval_cgroup_name,
                        self._CGROUP_SANDBOX_NAME,
                        self._CGROUP_LEAF,
                    ),
                ):
                    if any(c is None for c in cgroup_components):
                        continue
                    file_data = []
                    for filename in ("procs", "controllers", "subtree_control"):
                        data = None
                        try:
                            with self._open(
                                self._cgroup_path(
                                    *(cgroup_components + (f"cgroup.{filename}",))
                                ),
                                "rb",
                            ) as f:
                                data = f.read().decode("ascii").replace("\n", " ")
                        except Exception as e:
                            data = f"[fail: {e}]"
                        file_data.append(f"{filename}: {data}")
                    cgroup_components_joined = os.sep.join(cgroup_components)
                    file_data_joined = ", ".join(file_data)
                    cgroupfs_data.append(
                        f"{cgroup_components_joined}=[{file_data_joined}]"
                    )
                if len(cgroupfs_data) > 0:
                    cgroupfs_data_joined = " ".join(cgroupfs_data)
                    status_line += f" {cgroupfs_data_joined}"
            return status_line

        def _cgroup_path(self, *components):
            assert all(
                c is not None for c in components
            ), f"Tried to build cgroup path with not-yet-determined component: {components}"
            return os.path.join(self._CGROUP_ROOT, *(c for c in components if c))

        def _log(self, log_f, message):
            """
            Log a message to `log_f`.

            :param log_f: Log file object.
            """
            timestamp = time.strftime("%H:%M:%S")
            status = self._status()
            log_f.write(f"[{timestamp}] {message} [{status}]\n".encode("utf-8"))

        def do(self):
            """
            Do the switcheroo.

            :raises OSError: If anything goes wrong. Progress is saved.
            """
            op_index = -1
            for i, (op, _) in enumerate(self._operations):
                if self._checkpoint == op:
                    op_index = i
                    break
            with self._open(self._log_path, "ab") as log_f:

                def do_log(s):
                    return self._log(log_f, s)

                for op, fn in self._operations[op_index + 1 :]:
                    do_log(f"Starting operation: {op}")
                    errors = []
                    success = False
                    for attempt in range(1, 4):
                        try:
                            fn()
                        except OSError as e:
                            do_log(f"OSError #{attempt}: {op}: {e}")
                            errors.append(OSError(f"{op} (#{attempt}): {e}"))
                        except Exception as e:
                            do_log(f"Exception #{attempt}: {op}: {e}")
                            errors.append(OSError(f"{op} failed (#{attempt}): {e}"))
                        else:
                            success = True
                            break
                        time.sleep(0.1)
                    if success:
                        self._checkpoint = op
                        do_log(f"Success: {op}")
                        continue
                    assert len(errors) > 0, "Logic error"
                    first_exception = errors[0]
                    if len(errors) == 1:
                        raise first_exception
                    other_exceptions = "; ".join(str(e) for e in errors[1:])
                    raise errors[0].__class__(
                        f"{first_exception} (other attempts: {other_exceptions})"
                    )

        def _best_effort_remove_cgroup_subtree(self, codeeval_name):
            for cgroup_components in (
                (
                    self._initial_cgroup_name,
                    codeeval_name,
                    self._CGROUP_SANDBOX_NAME,
                    self._CGROUP_LEAF,
                ),
                (
                    self._initial_cgroup_name,
                    codeeval_name,
                    self._CGROUP_SUPERVISOR_NAME,
                    self._CGROUP_LEAF,
                ),
                (self._initial_cgroup_name, codeeval_name, self._CGROUP_SANDBOX_NAME),
                (
                    self._initial_cgroup_name,
                    codeeval_name,
                    self._CGROUP_SUPERVISOR_NAME,
                ),
                (self._initial_cgroup_name, codeeval_name),
            ):
                try:
                    os.rmdir(self._cgroup_path(*cgroup_components))
                except OSError:
                    pass

        def cleanup(self):
            if self._moved:
                self._move_process_back()
            if self._codeeval_cgroup_name is not None:
                self._best_effort_remove_cgroup_subtree(self._codeeval_cgroup_name)

        def _open(self, path, mode):
            try:
                return open(path, mode)
            except OSError as e:
                raise OSError(f"opening {path} mode={mode}: {e}")

        def _save_euid(self):
            self._my_euid = os.geteuid()

        def _save_egid(self):
            self._my_egid = os.getegid()

        def _unshare_user(self):
            Sandbox.unshare(
                os.CLONE_NEWUSER if "CLONE_NEWUSER" in os.__dict__ else 0x10000000
            )

        def _write_uid_map(self):
            with self._open("/proc/self/uid_map", "wb") as uid_map_f:
                uid_map_f.write(f"0 {self._my_euid} 1\n".encode("ascii"))

        def _write_setgroups(self):
            with self._open("/proc/self/setgroups", "wb") as setgroups_f:
                setgroups_f.write(b"deny")

        def _write_gid_map(self):
            with self._open("/proc/self/gid_map", "wb") as gid_map_f:
                gid_map_f.write(f"0 {self._my_egid} 1\n".encode("ascii"))

        def _find_self_in_cgroup_hierarchy(self):
            my_pid = os.getpid()
            cgroup_root_slash = self._CGROUP_ROOT + os.sep
            found_cgroup = None
            num_checked = 0
            num_except = 0
            sample_exception = None
            for dirpath, _, subfiles in os.walk(
                self._CGROUP_ROOT, onerror=None, followlinks=False
            ):
                if dirpath != self._CGROUP_ROOT and not dirpath.startswith(
                    cgroup_root_slash
                ):
                    continue
                if "cgroup.procs" not in subfiles:
                    continue
                num_checked += 1
                found_pid = False
                try:
                    with self._open(
                        os.path.join(dirpath, "cgroup.procs"), "rb"
                    ) as cgroup_procs_f:
                        for line in cgroup_procs_f:
                            for pid_str in line.strip().split(b" "):
                                if not pid_str:
                                    continue
                                try:
                                    pid = int(pid_str)
                                except ValueError:
                                    continue
                                if pid == my_pid:
                                    found_pid = True
                                    break
                except Exception as e:
                    num_except += 1
                    if sample_exception is None:
                        sample_exception = e.__class__(f"{dirpath}: {e}")
                    continue
                if not found_pid:
                    continue
                current_cgroup = dirpath[len(cgroup_root_slash) :]
                if found_cgroup is not None:
                    raise OSError(
                        f"Found PID {my_pid} in two separate cgroups: {found_cgroup} and {current_cgroup}; racing with another process?"
                    )
                found_cgroup = current_cgroup
            if found_cgroup is None:
                raise OSError(
                    f"PID {my_pid} could not be found in any cgroup (checked {num_checked} cgroups, {num_except} exceptions; sample: {sample_exception})"
                )
            if found_cgroup.endswith(os.sep + self._CGROUP_LEAF):
                found_cgroup = found_cgroup[: -len(os.sep + self._CGROUP_LEAF)]
            self._initial_cgroup_name = found_cgroup

        def _read_cgroup_controllers(self):
            cgroup_controllers = []
            with self._open(
                self._cgroup_path(self._initial_cgroup_name, "cgroup.controllers"), "rb"
            ) as cgroup_controllers_f:
                for line in cgroup_controllers_f:
                    for controller in line.strip().split(b" "):
                        if controller and controller not in cgroup_controllers:
                            cgroup_controllers.append(controller.decode("ascii"))
            self._cgroup_controllers = cgroup_controllers

        def _cleanup_old_cgroups(self):
            initial_cgroup_path = self._cgroup_path(self._initial_cgroup_name)
            for filename in os.listdir(initial_cgroup_path):
                if not filename.startswith(self._CGROUP_NAME_PREFIX):
                    continue
                cgroup_path = os.path.join(initial_cgroup_path, filename)
                if not os.path.isdir(cgroup_path):
                    continue
                self._best_effort_remove_cgroup_subtree(filename)

        def _create_initial_leaf_cgroup(self):
            try:
                os.mkdir(
                    self._cgroup_path(self._initial_cgroup_name, self._CGROUP_LEAF),
                    mode=0o755,
                )
            except FileExistsError:
                pass

        def _create_codeeval_cgroup(self):
            for counter in range(0, self._CGROUP_MAX_COUNT):
                codeeval_cgroup_name_candidate = f"{self._CGROUP_NAME_PREFIX}{counter}"
                cgroup_path = self._cgroup_path(
                    self._initial_cgroup_name, codeeval_cgroup_name_candidate
                )
                try:
                    os.mkdir(cgroup_path, mode=0o755)
                except FileExistsError:
                    pass
                else:
                    self._codeeval_cgroup_name = codeeval_cgroup_name_candidate
                    return
            initial_cgroup_path_prefix = self._cgroup_path(
                self._initial_cgroup_name, self._CGROUP_NAME_PREFIX
            )
            raise OSError(
                f"Out of cgroups (tried {initial_cgroup_path_prefix}NUM with NUM from 0 to {self._CGROUP_MAX_COUNT-1} and they all already exist)"
            )

        def _create_sandbox_cgroup(self):
            os.mkdir(
                self._cgroup_path(
                    self._initial_cgroup_name,
                    self._codeeval_cgroup_name,
                    self._CGROUP_SANDBOX_NAME,
                ),
                mode=0o755,
            )

        def _create_sandbox_leaf_cgroup(self):
            os.mkdir(
                self._cgroup_path(
                    self._initial_cgroup_name,
                    self._codeeval_cgroup_name,
                    self._CGROUP_SANDBOX_NAME,
                    self._CGROUP_LEAF,
                ),
                mode=0o755,
            )

        def _create_supervisor_cgroup(self):
            os.mkdir(
                self._cgroup_path(
                    self._initial_cgroup_name,
                    self._codeeval_cgroup_name,
                    self._CGROUP_SUPERVISOR_NAME,
                ),
                mode=0o755,
            )

        def _create_supervisor_leaf_cgroup(self):
            os.mkdir(
                self._cgroup_path(
                    self._initial_cgroup_name,
                    self._codeeval_cgroup_name,
                    self._CGROUP_SUPERVISOR_NAME,
                    self._CGROUP_LEAF,
                ),
                mode=0o755,
            )

        def _add_cgroup_controllers_to(self, *cgroup_components):
            add_controllers = tuple(
                controller
                for controller in self._cgroup_controllers
                if controller in self._needed_controllers
            )
            cgroup_components = tuple(cgroup_components) + ("cgroup.subtree_control",)
            cgroup_subtree_control_path = self._cgroup_path(*cgroup_components)
            try:
                with self._open(
                    cgroup_subtree_control_path, "wb"
                ) as cgroup_subtree_control_f:
                    controllers_data = (
                        " ".join(f"+{controller}" for controller in add_controllers)
                        + "\n"
                    )
                    cgroup_subtree_control_f.write(controllers_data.encode("ascii"))
            except OSError as e:
                raise OSError(
                    f"Adding controllers {add_controllers} on {cgroup_subtree_control_path}: {e}"
                )
            got_controllers = set()
            try:
                with self._open(
                    cgroup_subtree_control_path, "rb"
                ) as cgroup_subtree_control_f:
                    for line in cgroup_subtree_control_f:
                        for controller in line.strip().split(b" "):
                            if not controller:
                                continue
                            got_controllers.add(controller.decode("ascii"))
            except OSError as e:
                raise OSError(
                    f"Reading controllers from {cgroup_subtree_control_path}: {e}"
                )
            assert all(
                controller in got_controllers for controller in add_controllers
            ), f"Missing controllers in {cgroup_subtree_control_path}: got {got_controllers} expected {add_controllers}"

        def _add_cgroup_controllers_to_root(self):
            return self._add_cgroup_controllers_to(self._initial_cgroup_name)

        def _add_cgroup_controllers_to_codeeval(self):
            return self._add_cgroup_controllers_to(
                self._initial_cgroup_name, self._codeeval_cgroup_name
            )

        def _add_cgroup_controllers_to_sandbox(self):
            return self._add_cgroup_controllers_to(
                self._initial_cgroup_name,
                self._codeeval_cgroup_name,
                self._CGROUP_SANDBOX_NAME,
            )

        def _add_cgroup_controllers_to_supervisor(self):
            return self._add_cgroup_controllers_to(
                self._initial_cgroup_name,
                self._codeeval_cgroup_name,
                self._CGROUP_SUPERVISOR_NAME,
            )

        def _move_initial_cgroup_processes_to_initial_leaf_cgroup(self):
            initial_cgroup_procs_path = self._cgroup_path(
                self._initial_cgroup_name, "cgroup.procs"
            )
            initial_leaf_cgroup_procs_path = self._cgroup_path(
                self._initial_cgroup_name, self._CGROUP_LEAF, "cgroup.procs"
            )
            done_zero_pid = False
            while True:
                moving_process_pid = None
                with self._open(
                    initial_cgroup_procs_path, "rb"
                ) as initial_cgroup_procs_f:
                    for line in initial_cgroup_procs_f:
                        if moving_process_pid is not None:
                            continue
                        for pid_str in line.strip().split(b" "):
                            if not pid_str:
                                continue
                            try:
                                pid = int(pid_str)
                            except ValueError:
                                continue
                            if pid == 0:
                                if done_zero_pid:
                                    continue
                                done_zero_pid = True
                            moving_process_pid = pid
                            break
                if moving_process_pid is None:
                    break
                with self._open(
                    initial_leaf_cgroup_procs_path, "wb"
                ) as initial_leaf_cgroup_procs_f:
                    initial_leaf_cgroup_procs_f.write(
                        f"{moving_process_pid}\n".encode("ascii")
                    )

        def _move_process_to_supervisor_leaf(self):
            supervisor_leaf_cgroup_procs_path = self._cgroup_path(
                self._initial_cgroup_name,
                self._codeeval_cgroup_name,
                self._CGROUP_SUPERVISOR_NAME,
                self._CGROUP_LEAF,
                "cgroup.procs",
            )
            f = self._open(supervisor_leaf_cgroup_procs_path, "wb")
            try:
                f.write(b"0\n")
                self._moved = True
            finally:
                try:
                    f.close()
                except OSError:
                    pass

        def _move_process_back(self):
            initial_leaf_cgroup_procs_path = self._cgroup_path(
                self._initial_cgroup_name, self._CGROUP_LEAF, "cgroup.procs"
            )
            f = self._open(initial_leaf_cgroup_procs_path, "wb")
            try:
                f.write(b"0\n")
                self._moved = False
            finally:
                try:
                    f.close()
                except OSError:
                    pass

        def _set_cgroup_limits(self, *cgroup_components):
            cgroup_components = tuple(cgroup_components) + ("memory.max",)
            cgroup_memory_max_path = self._cgroup_path(*cgroup_components)
            if self._max_sandbox_ram_bytes is not None:
                try:
                    with self._open(cgroup_memory_max_path, "wb") as memory_max_f:
                        memory_max_f.write(
                            f"{self._max_sandbox_ram_bytes}\n".encode("ascii")
                        )
                except OSError as e:
                    raise OSError(
                        f"Trying to set max RAM limit to {self._max_sandbox_ram_bytes} bytes: {e}"
                    )
            for swap_type in ("swap", "zswap"):
                cgroup_swap_components = tuple(cgroup_components) + (
                    f"memory.{swap_type}.max",
                )
                cgroup_swap_path = self._cgroup_path(*cgroup_swap_components)
                if not os.path.exists(cgroup_swap_path):
                    continue
                try:
                    with self._open(cgroup_swap_path, "wb") as swap_max_f:
                        swap_max_f.write("0\n".encode("ascii"))
                except OSError as e:
                    raise OSError(
                        f"Trying to set max {swap_type} limit to 0 bytes: {e}"
                    )

        def _set_supervisor_cgroup_limits(self):
            return self._set_cgroup_limits(
                self._initial_cgroup_name,
                self._codeeval_cgroup_name,
                self._CGROUP_SUPERVISOR_NAME,
            )

        def _set_sandbox_cgroup_limits(self):
            return self._set_cgroup_limits(
                self._initial_cgroup_name,
                self._codeeval_cgroup_name,
                self._CGROUP_SANDBOX_NAME,
            )

        def _sanity_check_own_cgroup(self):
            supervisor_cgroup_path = self._cgroup_path(
                self._initial_cgroup_name,
                self._codeeval_cgroup_name,
                self._CGROUP_SUPERVISOR_NAME,
            )
            with self._open("/proc/self/cgroup", "rb") as cgroup_f:
                cgroup_data = cgroup_f.read().decode("ascii").strip()
            assert cgroup_data.endswith(
                os.sep + os.path.join(self._CGROUP_SUPERVISOR_NAME, self._CGROUP_LEAF)
            ), f"Unexpected self cgroup after moving to {supervisor_cgroup_path}: {cgroup_data}"

        def move_process_to_sandbox_leaf_cgroup_lambda(self):
            """
            Returns a function that can move the current process to the sandbox leaf cgroup.

            :return: A function to move the current process to the sandbox cgroup.
            :raises SandboxException: If not queried after we have already chosen a new cgroup name.
            """
            if not self._do_resource_limiting:
                return lambda: None
            if self._codeeval_cgroup_name is None:
                raise Sandbox.SandboxException(
                    "Tried to move process to sandbox leaf cgroup before we know it"
                )

            def _move(cgroup_path):
                """Dependency-free preexec_fn-compatible function to move to the given cgroup.procs."""
                try:
                    f = open(cgroup_path, "wb")
                except OSError as e:
                    raise OSError(f"Cannot open cgroup path {cgroup_path}: {e}")
                try:
                    f.write(b"0\n")
                except OSError as e:
                    raise OSError(f"Cannot move process to {cgroup_path}: {e}")
                finally:
                    try:
                        f.close()
                    except OSError:
                        pass
                clone_newcgroup = (
                    os.CLONE_NEWCGROUP
                    if "CLONE_NEWCGROUP" in os.__dict__
                    else 0x2000000
                )
                if "unshare" in os.__dict__:  # Python >= 3.12.
                    try:
                        os.unshare(clone_newcgroup)
                    except OSError as e:
                        raise OSError(f"unshare({clone_newcgroup}) failed: {e}")
                else:
                    import ctypes

                    libc = ctypes.CDLL(None)
                    libc.unshare.argtypes = [ctypes.c_int]
                    rc = libc.unshare(clone_newcgroup)
                    if rc == -1:
                        raise OSError(f"unshare({clone_newcgroup}) failed")

            sandbox_cgroup_procs_path = self._cgroup_path(
                self._initial_cgroup_name,
                self._codeeval_cgroup_name,
                self._CGROUP_SANDBOX_NAME,
                self._CGROUP_LEAF,
                "cgroup.procs",
            )[:]
            return lambda: _move(sandbox_cgroup_procs_path)

        def monitor_cgroup_resources(self):
            """
            Spawns a background thread that monitors resources, if limiting is enabled.
            cgroups should be taking care of this, but some systems do not
            enforce this. So this does the same in userspace.
            Better than nothing.

            :return: A function to cancel the monitor thread, if resource limiting is enabled.
            """
            if not self._do_resource_limiting:
                return lambda: None
            self_memory_path = self._cgroup_path(
                self._initial_cgroup_name,
                self._codeeval_cgroup_name,
                "memory.peak",
            )
            sandbox_procs_path = self._cgroup_path(
                self._initial_cgroup_name,
                self._codeeval_cgroup_name,
                self._CGROUP_SANDBOX_NAME,
                self._CGROUP_LEAF,
                "cgroup.procs",
            )

            def _kill():
                new_pids_to_kill = True
                pids_to_kill = set()
                while new_pids_to_kill:
                    prev_pids_to_kill_len = len(pids_to_kill)
                    with self._open(sandbox_procs_path, "rb") as cgroup_procs_f:
                        for line in cgroup_procs_f:
                            for pid_str in line.strip().split(b" "):
                                if not pid_str:
                                    continue
                                try:
                                    pid = int(pid_str)
                                except ValueError:
                                    continue
                                if pid != 0:
                                    pids_to_kill.add(pid)
                    for pid_to_kill in pids_to_kill:
                        try:
                            os.kill(pid_to_kill, signal.SIGKILL)
                        except Exception:
                            pass
                    new_pids_to_kill = prev_pids_to_kill_len < len(pids_to_kill)

            def _monitor():
                if self._max_sandbox_ram_bytes is not None:
                    try:
                        with self._open(self_memory_path, "rb") as memory_peak_f:
                            memory_peak_bytes = int(
                                memory_peak_f.read().decode("ascii").strip()
                            )
                        if memory_peak_bytes > self._max_sandbox_ram_bytes:
                            _kill()
                    except Exception as e:
                        print(
                            f"Warning: Failed to enforce code execution RAM: {e}",
                            file=sys.stderr,
                        )

            lock = threading.Lock()
            enabled = [True]

            def _loop():
                while True:
                    time.sleep(0.1)
                    with lock:
                        if not enabled[0]:
                            break
                    _monitor()

            monitor_thread = threading.Thread(
                target=_loop, name="Monitor thread for code execution", daemon=True
            )
            monitor_thread.start()

            def _cancel():
                with lock:
                    enabled[0] = False
                monitor_thread.join()

            return _cancel

    class SandboxException(Exception):
        """
        Base class for all exceptions generated by `Sandbox`.
        """

        def __init__(self, *args, **kwargs):
            self._sandbox_exception_args = tuple(args)
            self._sandbox_exception_kwargs = dict(kwargs)
            super().__init__(*args, **kwargs)

    class PlatformNotSupportedException(SandboxException):
        """
        Raised when the sandbox cannot run on the current platform.
        The only way to fix this is to run on a different platform.
        """

    class SandboxRuntimeException(SandboxException):
        """
        Raised when the sandbox fails to run properly.
        This means gVisor itself is failing, not the code in the sandbox.
        """

    class ExecutionError(subprocess.CalledProcessError):
        """
        Raised when the sandboxed code fails to run.
        This means the sandbox worked, but the code that ran within failed.
        """

        def __init__(self, code, **kwargs):
            super().__init__(**kwargs)
            self._code = code
            self._sandbox_exception_args = ()
            self._sandbox_exception_kwargs = kwargs.copy()
            self._sandbox_exception_kwargs["code"] = code

        def __str__(self):
            super_str = super().__str__()
            full_code = self._code
            short_code = full_code.replace("\n", ";")
            if len(short_code) >= 128:
                short_code = short_code[:60] + "\u2026" + short_code[-60:]
            if self.stderr:
                lines = [
                    line.strip() for line in self.stderr.split("\n") if line.strip()
                ]
                if len(lines) >= 2:
                    first_line, last_line = lines[0], lines[-1]
                    return f"{first_line} [\u2026] {last_line} (`{short_code}`)\n{super_str}\n```\n{full_code}\n```"
                if len(lines) == 1:
                    first_line = lines[0]
                    return f"{first_line} (`{short_code}`)\n{super_str}\n```\n{full_code}\n```"
            return f"`{short_code}` failed\n{super_str}\n```\n{full_code}\n```"

    class CodeExecutionError(ExecutionError):
        """
        Raised when the sandboxed code returns with a non-zero exit code.
        """

        def __str__(self):
            super_str = super().__str__()
            return f"Code error: {super_str}"

    class ExecutionTimeoutError(ExecutionError):
        """
        Raised when the code runs for too long relative to the timeout.
        """

        def __str__(self):
            super_str = super().__str__()
            return f"Timeout: {super_str}"

    class InterruptedExecutionError(ExecutionError):
        """
        Raised when the code runs but is interrupted before it finishes.
        This could happen from running out of resources.
        """

        def __str__(self):
            super_str = super().__str__()
            return f"Interrupted: {super_str}"

    class FixableException(SandboxException):
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
        Verifies that cgroupfs is mounted and usable for resource limiting.

        :return: Nothing.
        :raises EnvironmentNeedsSetupException: If cgroupfs is not mounted or unusable for resource limiting.
        """
        if not os.path.exists("/sys/fs/cgroup"):
            raise cls.EnvironmentNeedsSetupException(
                "cgroupfs not mounted as /sys/fs/cgroup but necessary for the sandbox to enforce memory limits; please mount it (`--mount=type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup,readonly=false`), or disable resource limiting if appropriate"
            )
        if not os.path.exists("/sys/fs/cgroup/cgroup.subtree_control"):
            raise cls.EnvironmentNeedsSetupException(
                "/sys/fs/cgroup/cgroup.subtree_control not found; make sure you are using cgroups v2, or disable resource limiting if appropriate"
            )
        # Try to open the file for writing to see if we can actually control cgroups.
        # They may be mounted read-only, as is default with Docker.
        try:
            with open(
                "/sys/fs/cgroup/cgroup.subtree_control", "wb"
            ) as subtree_control_f:
                pass
        except OSError:
            if os.geteuid() != 0:
                raise cls.EnvironmentNeedsSetupException(
                    "This script is not running as root, but it needs to do so in order to enforce resource limits; please run as root, or disable resource limiting if appropriate"
                )
            raise cls.EnvironmentNeedsSetupException(
                "cgroupfs is not mounted writable but necessary for the sandbox to enforce memory limits; please remount it as writable (`--mount=type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup,readonly=false`), or disable resource limiting if appropriate"
            )
        with open("/sys/fs/cgroup/cgroup.controllers", "rb") as subtree_control_f:
            controllers = subtree_control_f.read().decode("ascii").split(" ")
        if "memory" not in controllers:
            raise cls.EnvironmentNeedsSetupException(
                "cgroupfs does not have the 'memory' controller enabled, necessary to enforce memory limits; please enable it, or disable resource limiting if appropriate"
            )

    @classmethod
    def check_procfs(cls):
        """
        Verifies that we have an unobstructed view of procfs.

        :return: Nothing.
        :raises EnvironmentNeedsSetupException: If procfs is obstructed.
        """
        mount_infos = []
        with open("/proc/self/mountinfo", "rb") as mountinfo_f:
            for line in mountinfo_f:
                line = line.decode("utf-8").strip()
                if not line:
                    continue
                mount_components = line.split(" ")
                if len(mount_components) < 10:
                    continue
                hyphen_index = mount_components.index("-")
                if hyphen_index < 6:
                    continue
                mount_info = {
                    "mount_path": mount_components[4],
                    "path_within_mount": mount_components[3],
                    "fs_type": mount_components[hyphen_index + 1],
                }
                mount_infos.append(mount_info)
        procfs_mounts = frozenset(
            m["mount_path"]
            for m in mount_infos
            if m["fs_type"] == "proc" and m["path_within_mount"] == "/"
        )
        if len(procfs_mounts) == 0:
            raise cls.EnvironmentNeedsSetupException(
                "procfs is not mounted; please mount it"
            )
        obstructed_procfs_mounts = set()
        for mount_info in mount_infos:
            for procfs_mount in procfs_mounts:
                if mount_info["mount_path"].startswith(procfs_mount + os.sep):
                    obstructed_procfs_mounts.add(procfs_mount)
        for procfs_mount in procfs_mounts:
            if procfs_mount not in obstructed_procfs_mounts:
                return  # We have at least one unobstructed procfs view.
        assert len(obstructed_procfs_mounts) > 0, "Logic error"
        raise cls.EnvironmentNeedsSetupException(
            "procfs is obstructed; please mount a new procfs mount somewhere in the container, e.g. /proc2 (`--mount=type=bind,source=/proc,target=/proc2,readonly=false,bind-recursive=disabled`)"
        )

    @classmethod
    def unshare(cls, flags):
        """
        Implementation of `os.unshare` that works on Python < 3.12.

        :param flags: Flags to pass to the `unshare(2)` system call.
        :raises OSError: If something goes wrong.
        """
        if "unshare" in os.__dict__:  # Python >= 3.12.
            return os.unshare(flags)

        # Python <= 3.11:
        return cls._libc().unshare(flags)

    @classmethod
    def check_unshare(cls):
        """
        Verifies that the `unshare(2)` system call is available.

        :return: Nothing.
        :raises EnvironmentNeedsSetupException: If `unshare(2)` is not available.
        """
        try:
            cls.unshare(0)
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
        cls,
        language: str,
        auto_install_allowed: bool,
        require_resource_limiting: bool,
    ):
        """
        Verifies that the environment is compatible with running sandboxes.

        :param language: The programming language to run.
        :param auto_install_allowed: Whether auto-installation of `runsc` is allowed.
        :param require_resource_limiting: Check that the host supports resource limiting via cgroups.

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
        if require_resource_limiting:
            cls.check_cgroups()
        cls.check_procfs()
        if not auto_install_allowed and cls.get_runsc_path() is None:
            raise cls.GVisorNotInstalledException(
                "gVisor is not installed (runsc binary not found in $PATH); please install it or enable AUTO_INSTALL valve for auto installation"
            )

    @classmethod
    def _libc(cls):
        if cls._LIBC is None:
            cls._LIBC = cls._Libc()
        return cls._LIBC

    @classmethod
    def main(cls):
        """
        Entry-point for (re-)execution.
        Must be called during import.
        May call `sys.exit` if this is intended to be a code evaluation re-execution.
        """
        cls._SelfFile.init()
        if cls._MARKER_ENVIRONMENT_VARIABLE not in os.environ:
            return
        try:
            directives = json.load(sys.stdin)
            sandbox = cls(**directives["settings"])
            if directives["stage"] == cls._STAGE_SANDBOX:
                result = sandbox._run()
            elif directives["stage"] == cls._STAGE_SNIPPET:
                result = sandbox._run_snippets()
            else:
                raise ValueError(f"Invalid stage in directives: {directives}")
        except Exception as e:
            exception_info = {
                "name": e.__class__.__name__,
                "str": str(e),
            }
            if isinstance(e, cls.SandboxException) or isinstance(e, cls.ExecutionError):
                exception_info["args"] = e._sandbox_exception_args
                exception_info["kwargs"] = e._sandbox_exception_kwargs
            json.dump(
                {
                    "exception": exception_info,
                },
                sys.stdout,
            )
        else:
            stdout = result.stdout
            if type(stdout) is not type(b""):
                stdout = stdout.encode("utf-8", errors="replace")
            stderr = result.stderr
            if type(stderr) is not type(b""):
                stderr = stderr.encode("utf-8", errors="replace")
            json.dump(
                {
                    "result": {
                        "args": result.args,
                        "returncode": result.returncode,
                        "stdout": base64.b64encode(stdout).decode("utf-8"),
                        "stderr": base64.b64encode(stderr).decode("utf-8"),
                    },
                },
                sys.stdout,
            )
        finally:
            sys.stdout.flush()
            sys.exit(0)

    def __init__(
        self,
        tmp_dir: str,
        snippets: list[tuple],
        debug: bool,
        networking_allowed: bool,
        max_runtime_seconds: int,
        max_ram_bytes: typing.Optional[int] = None,
        require_resource_limiting: bool = False,
        persistent_home_dir: typing.Optional[str] = None,
    ):
        """
        Constructor.

        :param tmp_dir: Temporary directory exclusive to this sandbox. Must outlive the Sandbox object.
        :param snippets: A list of 2-tuples (language, code) to run inside the sandbox.
        :param debug: Whether or not to enable debug-level logging for the sandbox.
        :param networking_allowed: Whether the code should be given access to the network.
        :param max_runtime_seconds: How long the code should be allowed to run, in seconds.
        :param max_ram_bytes: How many bytes of RAM the interpreter should be allowed to use, or `None` for no limit.
        :param require_resource_limiting: If true, refuse to launch a sandbox if the host doesn't support resource limiting via cgroups.
        :param persistent_home_dir: Optional directory which will be mapped read-write to this real host directory.
        """
        self._init(
            {
                "tmp_dir": tmp_dir,
                "snippets": snippets,
                "debug": debug,
                "networking_allowed": networking_allowed,
                "max_runtime_seconds": max_runtime_seconds,
                "max_ram_bytes": max_ram_bytes,
                "require_resource_limiting": require_resource_limiting,
                "persistent_home_dir": persistent_home_dir,
            }
        )

    def _init(self, settings):
        self._settings = settings
        self._tmp_dir = self._settings["tmp_dir"]
        self._bundle_path = os.path.join(self._tmp_dir, "bundle")
        self._runtime_root_path = os.path.join(self._tmp_dir, "runtime")
        self._logs_path = os.path.join(self._tmp_dir, "logs")
        self._gotmp_dir = os.path.join(self._tmp_dir, "gotmp")
        self._sandbox_shared_path = os.path.join(self._tmp_dir, "sandbox")
        self._snippets = self._settings["snippets"]
        self._debug = self._settings["debug"]
        self._networking_allowed = self._settings["networking_allowed"]
        self._max_runtime_seconds = self._settings["max_runtime_seconds"]
        self._max_ram_bytes = self._settings["max_ram_bytes"]
        self._require_resource_limiting = self._settings[
            "require_resource_limiting"
        ] or all((self._max_ram_bytes is None,))
        self._persistent_home_dir = self._settings["persistent_home_dir"]
        self._sandboxed_command = None
        self._switcheroo = None

    def _setup_sandbox(self):
        """
        Set up the sandbox's root filesystem and OCI config prior to execution.
        Runs in separate forked process. Performs the switcheroo.

        :raises FixableException: If an issue occurs but that can be fixed by the user.
        """
        # Set up basic configuration options.
        oci_config = copy.deepcopy(self.OCI_CONFIG_SKELETON)
        tz = os.environ.get("TZ")
        if tz:
            oci_config["process"]["env"].append(f"TZ={tz}")
        if self._max_ram_bytes:
            oci_config["linux"]["resources"]["memory"]["limit"] = self._max_ram_bytes
        os.makedirs(self._bundle_path, mode=0o711)
        os.makedirs(self._runtime_root_path, mode=0o711)
        os.makedirs(self._logs_path, mode=0o711)
        os.makedirs(self._sandbox_shared_path, mode=0o777)
        os.makedirs(self._gotmp_dir, mode=0o711)
        os.chmod(self._sandbox_shared_path, mode=0o777, follow_symlinks=False)
        rootfs_path = os.path.join(self._tmp_dir, "rootfs")
        os.makedirs(rootfs_path, mode=0o755)
        if self._persistent_home_dir is not None:
            if not os.path.isdir(self._persistent_home_dir):
                raise self.SandboxException(
                    f"Persistent home directory {self._persistent_home_dir} does not exist"
                )
        oci_config["root"]["path"] = rootfs_path
        do_resource_limiting = True
        if not self._require_resource_limiting:
            try:
                self.check_cgroups()
            except self.EnvironmentNeedsSetupException:
                do_resource_limiting = False
        self._switcheroo = self._Switcheroo(
            libc=self._libc(),
            log_path=os.path.join(self._logs_path, "switcheroo.txt"),
            max_sandbox_ram_bytes=self._max_ram_bytes,
            do_resource_limiting=do_resource_limiting,
        )
        try:
            self._switcheroo.do()
        except Exception as e:
            try:
                switcheroo_status = self._switcheroo._status()
            except Exception:
                raise e
            else:
                raise e.__class__(f"{e}; {switcheroo_status}")

        # Mount the Python interpreter.
        oci_config["mounts"].append(
            {
                "type": "bind",
                "source": sys.executable,
                "destination": sys.executable,
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
        for d in self.EMPTY_READ_ONLY_DIRECTORIES + [os.path.dirname(sys.executable)]:
            rootfs_subdir = os.path.join(rootfs_path, d.removeprefix(os.path.sep))
            os.makedirs(rootfs_subdir, mode=0o755, exist_ok=True)

        # Handle exposed host symlinks. These will show up as symlinks with the same
        # target path in the sandbox, so they do not expose the host's view of the
        # directory they point to.
        symlinks = set()
        for p in self.EXPOSED_SYSTEM_DIRECTORIES + self.EXPOSED_SYSTEM_FILES:
            if not os.path.islink(p):
                continue
            rootfs_subpath = os.path.join(rootfs_path, p.removeprefix(os.path.sep))
            os.makedirs(os.path.dirname(rootfs_subpath), mode=0o755, exist_ok=True)
            os.symlink(src=os.readlink(p), dst=rootfs_subpath)
            symlinks.add(p)

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

        # Shared sandbox directory to propagate and persistent files.
        oci_config["mounts"].append(
            {
                "type": "bind",
                "source": self._sandbox_shared_path,
                "destination": "/sandbox",
                "options": ["rw"],
            }
        )
        with open(os.path.join(self._sandbox_shared_path, "self.py"), "w") as self_f:
            self_f.write(self._SelfFile.contents())
        if self._persistent_home_dir is not None:
            oci_config["mounts"].append(
                {
                    "type": "bind",
                    "source": self._persistent_home_dir,
                    "destination": "/sandbox/persistent",
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
        oci_config["process"]["env"].append(f"{self._MARKER_ENVIRONMENT_VARIABLE}=1")
        self._sandboxed_command = [
            sys.executable,
            "/sandbox/self.py",
        ]

        # Work around issue that gVisor does not preserve correct UID mappings when running as non-root user in the sandbox.
        # So map current user to 0:0, then create a new user namespace immediately before running command and remap to
        # correct UID/GID.
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

    def _process_json_wrapped_result(
        self, result: subprocess.CompletedProcess
    ) -> subprocess.CompletedProcess:
        """
        Process a `CompletedProcess` from a wrapped invocation.

        :param result: A `CompletedProcess` with stdout captured.
        :return: A synthetic `CompletedProcess` from the JSON information in stdout.
        :raises Sandbox.SandboxRuntimeException: If the JSON information cannot be interpreted.
        :raises Sandbox.SandboxException: For any exception that is forwarded.
        """
        if not result.stdout:
            raise self.SandboxRuntimeException(
                f"Subprocess interpreter did not produce any output (stderr: {result.stderr})"
            )
        try:
            output = json.loads(result.stdout)
        except json.decoder.JSONDecodeError as e:
            raise self.SandboxRuntimeException(
                f"Subprocess interpreter produced invalid JSON (stdout: {result.stdout}): {e}"
            )
        if "exception" in output:
            class_name = output["exception"]["name"]
            found_class = None
            for ex_class in (
                self.PlatformNotSupportedException,
                self.SandboxRuntimeException,
                self.CodeExecutionError,
                self.ExecutionTimeoutError,
                self.InterruptedExecutionError,
                self.GVisorNotInstalledException,
                self.CorruptDownloadException,
                self.EnvironmentNeedsSetupException,
                self.ExecutionError,
                self.SandboxException,
            ):
                if ex_class.__name__ == class_name:
                    found_class = ex_class
                    break
            if found_class is None:
                exception_str = output["exception"]["str"]
                raise self.SandboxRuntimeException(f"{class_name}: {exception_str}")
            raise found_class(
                *output["exception"]["args"], **output["exception"]["kwargs"]
            )
        if "result" not in output:
            raise self.SandboxRuntimeException(
                f"Invalid response from subprocess: {output}"
            )
        return subprocess.CompletedProcess(
            args=output["result"]["args"],
            returncode=output["result"]["returncode"],
            stdout=base64.b64decode(output["result"]["stdout"]).decode(
                "utf-8", errors="replace"
            ),
            stderr=base64.b64decode(output["result"]["stderr"]).decode(
                "utf-8", errors="replace"
            ),
        )

    def _run(self) -> subprocess.CompletedProcess:
        """
        Spawn and wait for the sandbox. Runs in separate forked process.

        :return: A `CompletedProcess` object representing the return code and stdout/stderr of the code interpreter.
        :raises Sandbox.SandboxRuntimeException: If the sandbox failed to start or behaved incorrectly regardless of the code being evaluated.
        :raises Sandbox.ExecutionTimeoutError: If the code interpreter ran for longer than configured.
        :raises Sandbox.InterruptedExecutionError: If the code interpreter died without providing a return code; usually due to running over resource limits.
        :raises sandbox.CodeExecutionError: If the code interpreter failed to execute the given code. This does not represent a sandbox failure.
        """
        try:
            self._setup_sandbox()

            network_mode = "host" if self._networking_allowed else "none"
            runsc_argv = [
                self.get_runsc_path(),
                "--rootless=true",
                "--directfs=false",
                f"--network={network_mode}",
                "--ignore-cgroups=true",  # We already took care of cgroups manually.
                f"--root={self._runtime_root_path}",
                f"--debug-log={self._logs_path}/",
                "run",
                f"--bundle={self._bundle_path}",
                "sandbox",
            ]
            runsc_env = os.environ.copy()
            runsc_env["TMPDIR"] = self._gotmp_dir
            runsc_input = json.dumps(
                {
                    "stage": self._STAGE_SNIPPET,
                    "settings": self._settings,
                }
            )
            started_marker_path = os.path.join(self._sandbox_shared_path, "started")
            resource_monitor_cancel = self._switcheroo.monitor_cgroup_resources()
            try:
                result = subprocess.run(
                    runsc_argv,
                    env=runsc_env,
                    preexec_fn=self._switcheroo.move_process_to_sandbox_leaf_cgroup_lambda(),
                    input=runsc_input,
                    text=True,
                    capture_output=True,
                    timeout=self._max_runtime_seconds + 3,
                    check=True,
                )
            except subprocess.TimeoutExpired as e:
                raise self.ExecutionTimeoutError(
                    code="; ".join(
                        f"({language}, {repr(code)}))"
                        for language, code in self._snippets
                    ),
                    returncode=126,
                    cmd=self._sandboxed_command,
                    output=e.stdout,
                    stderr=e.stderr,
                )
            except subprocess.CalledProcessError as e:
                if os.path.isfile(started_marker_path):
                    raise self.InterruptedExecutionError(
                        code="; ".join(
                            f"({language}, {repr(code)}))"
                            for language, code in self._snippets
                        ),
                        returncode=127,
                        cmd=self._sandboxed_command,
                        output=e.stdout,
                        stderr=e.stderr,
                    )
                logs = {}

                def process_log(filename, log_line):
                    if self._debug or (
                        log_line and log_line[0] in "WEF"
                    ):  # Warning, Error, Fatal
                        if filename not in logs:
                            logs[filename] = []
                        logs[filename].append(log_line)

                self.debug_logs(process_log)
                stderr = e.stderr.strip()
                json_logs = json.dumps(logs)
                if self._debug:
                    raise self.SandboxRuntimeException(
                        f"Sandbox failed to start: {e}; stderr: {stderr}; logs: {json_logs}"
                    )
                raise self.SandboxRuntimeException(
                    f"Sandbox failed to start: {e} (turn on debug mode to see more information); stderr: {stderr}; logs: {json_logs}"
                )
            finally:
                resource_monitor_cancel()
            if not os.path.isfile(started_marker_path):
                raise self.SandboxRuntimeException(
                    "Sandbox failed to start up properly"
                )
            return self._process_json_wrapped_result(result)
        finally:
            if self._switcheroo is not None:
                self._switcheroo.cleanup()

    def _run_snippets(self):
        """
        Run all snippets in the sandbox.
        This code is called from *within* the gVisor sandbox.
        """
        with open("/sandbox/started", "wb") as started_f:
            started_f.write(b"OK\n")
        deadline = time.time() + self._max_runtime_seconds
        last_result = None
        overall_args = []
        overall_stdout = ""
        overall_stderr = ""
        if len(self._snippets) == 0:
            raise self.SandboxRuntimeException("No code snippets to run")
        for snippet in self._snippets:
            if len(snippet) != 2:
                raise self.SandboxRuntimeException(f"Invalid snippet: {snippet}")
            language, code = snippet
            if language not in self.SUPPORTED_LANGUAGES:
                raise self.SandboxRuntimeException(f"Unsupported language: {language}")
            interpreter_path = None
            if language == self.LANGUAGE_BASH:
                interpreter_path = shutil.which("bash")
            elif language == self.LANGUAGE_PYTHON:
                interpreter_path = sys.executable
            if interpreter_path is None:
                raise self.SandboxRuntimeException(
                    f"Cannot find interpreter for language: {language}"
                )
            cmd = [interpreter_path, "/dev/stdin"]
            overall_args.append(" ".join(cmd))
            snippet_timeout = deadline - time.time()
            if snippet_timeout <= 0.0:
                raise self.ExecutionTimeoutError(
                    f"Code executed the deadline of {self._max_runtime_seconds} seconds"
                )
            try:
                snippet_result = subprocess.run(
                    cmd,
                    input=code + "\n",
                    text=True,
                    capture_output=True,
                    timeout=snippet_timeout,
                    check=True,
                )
            except subprocess.TimeoutExpired as e:
                overall_stdout += e.stdout or ""
                overall_stderr += e.stderr or ""
                raise self.ExecutionTimeoutError(
                    code=code,
                    returncode=126,
                    cmd=["sh", "-c", "; ".join(overall_args)],
                    output=overall_stdout,
                    stderr=overall_stderr,
                )
            except subprocess.CalledProcessError as e:
                overall_stdout += e.stdout or ""
                overall_stderr += e.stderr or ""
                raise self.CodeExecutionError(
                    code=code,
                    returncode=e.returncode,
                    cmd=["sh", "-c", "; ".join(overall_args)],
                    output=overall_stdout,
                    stderr=overall_stderr,
                )
            else:
                last_result = snippet_result
                overall_stdout += snippet_result.stdout or ""
                overall_stderr += snippet_result.stderr or ""
        assert last_result is not None, "Logic error"
        if os.path.isdir("/sandbox/persistent"):
            shutil.copytree(
                "/home/user",
                "/sandbox/persistent",
                ignore_dangling_symlinks=True,
                dirs_exist_ok=True,
            )
        return subprocess.CompletedProcess(
            args=["sh", "-c", "; ".join(overall_args)],
            returncode=0,
            stdout=overall_stdout,
            stderr=overall_stderr,
        )

    def run(self) -> subprocess.CompletedProcess:
        """
        Set up and run the sandbox in a separate process.

        :return: A `CompletedProcess` object representing the return code and stdout/stderr of the code interpreter.
        :raises FixableException: If an issue occurs but that can be fixed by the user.
        :raises Sandbox.SandboxRuntimeException: If the sandbox failed to start or behaved incorrectly regardless of the code being evaluated.
        :raises Sandbox.ExecutionTimeoutError: If the code interpreter ran for longer than configured.
        :raises Sandbox.InterruptedExecutionError: If the code interpreter died without providing a return code; usually due to running over resource limits.
        :raises sandbox.CodeExecutionError: If the code interpreter failed to execute the given code. This does not represent a sandbox failure.
        """
        reexec_path = os.path.join(self._tmp_dir, "self.py")
        with open(reexec_path, "w") as reexec_f:
            reexec_f.write(self._SelfFile.contents())
        new_env = os.environ.copy()
        new_env[self._MARKER_ENVIRONMENT_VARIABLE] = "1"
        directives = json.dumps(
            {
                "stage": self._STAGE_SANDBOX,
                "settings": self._settings,
            }
        )
        try:
            result = subprocess.run(
                (sys.executable, reexec_path),
                env=new_env,
                input=directives,
                text=True,
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise self.SandboxRuntimeException(f"{e} (stderr: {e.stderr})")
        else:
            return self._process_json_wrapped_result(result)

    def debug_logs(self, write_fn: typing.Callable[[str, str], typing.Any]):
        """
        Write debug logs and other system information to the given function.

        May only be called after `run` returns, but may be called even when
        `run` fails.

        :param write_fn: A function that takes (filename, log line) as arguments.
        """
        log_paths = []
        all_logs = []
        if os.path.isdir(self._logs_path):
            for log_filename in sorted(os.listdir(self._logs_path)):
                if not log_filename.endswith(".txt"):
                    continue
                log_paths.append(os.path.join(self._logs_path, log_filename))
        else:
            all_logs.append(
                (
                    "[meta]",
                    f"Logs path {self._logs_path} does not exist or is not a directory.",
                )
            )
        log_paths.extend(self._EXTRA_DEBUG_LOG_PATHS)
        runsc_filenames = set()
        for log_path in log_paths:
            log_filename = os.path.basename(log_path)
            if log_filename.startswith("runsc.log.") and log_filename.endswith(".txt"):
                log_filename = "runsc." + self._LOG_FILENAME_TRUNCATE_RE.sub(
                    "", log_filename
                ).removesuffix(".txt")
                if log_filename in runsc_filenames:
                    runsc_filename_suffix = 2
                    while f"{log_filename}.{runsc_filename_suffix}" in runsc_filenames:
                        runsc_filename_suffix += 1
                    log_filename = f"{log_filename}.{runsc_filename_suffix}"
                runsc_filenames.add(log_filename)
            try:
                with open(log_path, "rb") as log_f:
                    for log_line in log_f:
                        log_line = log_line.replace(b"\x00", b"\n").rstrip()
                        if not log_line:
                            continue
                        for line in log_line.split(b"\n"):
                            all_logs.append(
                                (log_filename, line.decode("utf-8", errors="replace"))
                            )
            except Exception as e:
                all_logs.append((log_filename, f"Failed to open: {e}"))
        for cmd in self._EXTRA_DEBUG_LOG_COMMANDS:
            cmd_str = "`" + " ".join(cmd) + "`"
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=1, check=True)
            except subprocess.CalledProcessError as e:
                all_logs.append(
                    (cmd_str, f"Failed: {e} (stdout={e.stdout}, stderr={e.stderr})")
                )
            except Exception as e:
                all_logs.append((cmd_str, f"Failed: {e}"))
            else:
                for line in result.stdout.replace(b"\x00", b"\n").split(b"\n"):
                    line = line.rstrip()
                    if not line:
                        continue
                    all_logs.append((cmd_str, line.decode("utf-8", errors="replace")))
        for filename, log_entry in all_logs:
            write_fn(filename, log_entry)


Sandbox.main()


class UpdateCheck:
    """
    Check for updates.
    """

    RELEASES_URL = "https://github.com/EtiennePerot/safe-code-execution/releases.atom"
    USER_URL = "https://github.com/EtiennePerot/safe-code-execution/"
    ENABLED = True
    SELF_VERSION = None
    LAST_UPDATE_CHECK = None
    LAST_UPDATE_CACHE = None
    UPDATE_CHECK_INTERVAL = datetime.timedelta(days=3)
    VERSION_REGEX = re.compile(r"<title>\s*(v?\d+(?:\.\d+)+)\s*</title>")

    class VersionCheckError(Exception):
        pass

    @staticmethod
    def _parse_version(version_str):
        return tuple(int(c) for c in version_str.strip().removeprefix("v").split("."))

    @staticmethod
    def _format_version(version):
        return "v" + ".".join(str(c) for c in version)

    @staticmethod
    def _compare(version_a, version_b):
        """
        Returns -1 if version_a < version_b, 0 if equal, 1 if greater.
        """
        for a, b in zip(version_a, version_b):
            if a < b:
                return -1
            if a > b:
                return 1
        return len

    @classmethod
    def disable(cls):
        cls.ENABLED = False

    @classmethod
    def init_from_frontmatter(cls, file_with_frontmatter):
        if not cls.ENABLED:
            return
        with open(file_with_frontmatter, "rb") as f:
            contents = f.read().decode("ascii").strip()
        if not contents.startswith('"""'):
            raise cls.VersionCheckError(
                f"Malformed file contents: {contents[:min(8, len(contents))]}[...]"
            )
        contents = contents[len('"""') :].strip()
        version = None
        for line in contents.split("\n"):
            line = line.strip()
            if line == '"""':
                break
            if line.startswith("version:"):
                if version is not None:
                    raise cls.VersionCheckError(
                        f"Multiple 'version' lines found: {version} and {line}"
                    )
                version = line[len("version:") :].strip()
        if version is None:
            raise cls.VersionCheckError("Version metadata not found")
        cls.SELF_VERSION = cls._parse_version(version)

    @classmethod
    def _get_current_version(cls):
        assert (
            cls.SELF_VERSION is not None
        ), "UpdateCheck.init_from_frontmatter must be called first."
        return cls.SELF_VERSION

    @classmethod
    def need_check(cls):
        if cls.LAST_UPDATE_CHECK is None:
            return True
        return (
            datetime.datetime.now() - cls.LAST_UPDATE_CHECK >= cls.UPDATE_CHECK_INTERVAL
        )

    @classmethod
    def _get_latest_version(cls):
        if not cls.need_check():
            if type(cls.LAST_UPDATE_CACHE) is type(()):
                return cls.LAST_UPDATE_CACHE
            raise cls.LAST_UPDATE_CACHE
        try:
            try:
                releases_xml = urllib.request.urlopen(url=cls.RELEASES_URL).read()
            except urllib.error.HTTPError as e:
                cls.LAST_UPDATE_CACHE = cls.VersionCheckError(
                    f"Failed to retrieve latest version: {e} (URL: {cls.RELEASES_URL})"
                )
                raise cls.LAST_UPDATE_CACHE
            latest_version = None
            for match in cls.VERSION_REGEX.finditer(releases_xml.decode("utf-8")):
                version = cls._parse_version(match.group(1))
                if latest_version is None or cls._compare(version, latest_version) == 1:
                    latest_version = version
            if latest_version is None:
                cls.LAST_UPDATE_CACHE = cls.VersionCheckError(
                    f"Failed to retrieve latest version: no release found (URL: {cls.RELEASES_URL})"
                )
                raise cls.LAST_UPDATE_CACHE
            cls.LAST_UPDATE_CACHE = latest_version
            return latest_version
        finally:
            cls.LAST_UPDATE_CHECK = datetime.datetime.now()

    @classmethod
    def get_newer_version(cls) -> typing.Optional[str]:
        """
        Check for the latest version and return it if newer than current.

        :raises VersionCheckError: If there was an error checking for version.
        :return: The latest version number if newer than current, else None.
        """
        if not cls.ENABLED:
            return None
        try:
            current_version = cls._get_current_version()
        except cls.VersionCheckError as e:
            raise e.__class__(f"Checking current version: {e}")
        try:
            latest_version = cls._get_latest_version()
        except cls.VersionCheckError as e:
            raise e.__class__(f"Checking latest version: {e}")
        if cls._compare(current_version, latest_version) == -1:
            return cls._format_version(latest_version)
        return None


UpdateCheck.init_from_frontmatter(os.path.abspath(__file__))
# fmt: on


_SAMPLE_BASH_INSTRUCTIONS = (
    "echo 'Hello from the sandbox!'",
    "date",
    "dmesg",
    "echo 'Bye from the sandbox!'",
)

_SAMPLE_PYTHON_INSTRUCTIONS = (
    "print('Hello from the sandbox!')",
    "import datetime, sys",
    "print('Current date and time:', datetime.datetime.now())",
    "sys.stdout.flush()",
    "import shutil, subprocess",
    "subprocess.run([shutil.which('dmesg')], check=True)",
    "print('Bye from the sandbox!')",
)


def _do_self_tests(debug):
    _self_tests = (
        {
            "name": "simple_python",
            "language": "python",
            "code": _SAMPLE_PYTHON_INSTRUCTIONS,
            "debug": True,
            "status": "OK",
        },
        {
            "name": "simple_bash",
            "language": "bash",
            "code": _SAMPLE_BASH_INSTRUCTIONS,
            "debug": True,
            "status": "OK",
        },
        {
            "name": "bad_syntax_python",
            "language": "python",
            "code": ("print('foo",),
            "debug": True,
            "status": "ERROR",
        },
        {
            "name": "bad_syntax_bash",
            "language": "bash",
            "code": ("echo 'foo",),
            "debug": True,
            "status": "ERROR",
        },
        {
            "name": "long_running_code",
            "language": "python",
            "code": (
                "import time",
                "time.sleep(15)",
                "print('Managed to sleep for 15 seconds.')",
            ),
            "valves": {
                "MAX_RUNTIME_SECONDS": 5,
            },
            "status": "TIMEOUT",
        },
        {
            "name": "ram_hog",
            "language": "python",
            "code": (
                "import time",
                "f = open('/dev/urandom', 'rb')",
                "s = []",
                "for i in range(256): s.append(f.read(1024 * 1024))",
                "time.sleep(1)",
                "print('\\n'.join(line for line in open('/proc/self/status').read().split('\\n') if line.startswith('Vm')))",
                "print('Managed to hog', len(s), 'megabytes.')",
            ),
            "valves": {
                "MAX_RAM_MEGABYTES": 128,
            },
            "status": "INTERRUPTED",
        },
    )

    def _print_output(obj):
        if obj.stdout:
            print("  \U0001f5e8 Output:", file=sys.stderr)
            for stdout_line in obj.stdout.split("\n"):
                print(f"    {stdout_line}")
        if obj.stderr:
            print("  \U0001f41e Debug:", file=sys.stderr)
            for stderr_line in obj.stderr.split("\n"):
                print(f"    {stderr_line}")

    success = True
    for self_test in _self_tests:
        name = self_test["name"]
        language = self_test["language"]
        code = "\n".join(self_test["code"]) + "\n"
        want_status = self_test["status"]
        valves = self_test.get("valves", {})
        test_env = os.environ.copy()
        for valve_name, valve_value in valves.items():
            test_env[
                _Tools.Valves()._VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX
                + valve_name
            ] = str(valve_value)
        test_argv = [
            sys.executable,
            os.path.abspath(__file__),
            f"--language={language}",
        ]
        if debug or self_test.get("debug", False):
            test_argv.append("--debug")
        print(f"\u23f3 Running self-test: {name}", file=sys.stderr)
        try:
            result = subprocess.run(
                test_argv,
                env=test_env,
                input=code,
                text=True,
                capture_output=True,
                timeout=20,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            success = False
            _print_output(e)
            print(
                f"\u274c Self-test {name} failed: process failed: {e}", file=sys.stderr
            )
        except Exception as e:
            success = False
            exception_class = e.__class__
            print(
                f"\u274c Self-test {name} failed: {exception_class}: {e}",
                file=sys.stderr,
            )
        else:
            try:
                result_data = json.loads(result.stdout)
            except json.decoder.JSONDecodeError as e:
                _print_output(result)
                success = False
                print(
                    f"\u274c Self-test {name} failed: JSON decoding failed: {e}",
                    file=sys.stderr,
                )
            else:
                got_status = result_data["status"]
                if got_status != want_status:
                    _print_output(result)
                    success = False
                    print(
                        f"\u274c Self-test {name} failed: status was {got_status}, expected {want_status}",
                        file=sys.stderr,
                    )
                else:
                    if debug:
                        _print_output(result)
                    print(f"\u2714 Self-test {name} passed.", file=sys.stderr)
    if success:
        print("\u2705 All tool self-tests passed, good go to!", file=sys.stderr)
        sys.exit(0)
    else:
        print("\u2620 One or more tool self-tests failed.", file=sys.stderr)
        sys.exit(1)
    assert False, "Unreachable"


# Debug utility: Run code from stdin if running as a normal Python script.
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run arbitrary code in a gVisor sandbox."
    )
    parser.add_argument(
        "--language",
        choices=("python", "bash"),
        default="python",
        help="Language of the code to run.",
    )
    parser.add_argument(
        "--use_sample_code",
        action="store_true",
        default=False,
        help="Run sample code for the given language; otherwise, read code from stdin.",
    )
    parser.add_argument(
        "--self_test",
        action="store_true",
        default=False,
        help="Run series of self-tests.",
    )
    parser.add_argument(
        "--debug", action="store_true", default=False, help="Enable debug mode."
    )
    parser.add_argument(
        "--want_status",
        type=str,
        default="",
        help="If set, verify that the code evaluation status matches this or exit with error code.",
    )
    args = parser.parse_args()

    if args.debug:
        os.environ[
            _Tools.Valves()._VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX + "DEBUG"
        ] = "true"

    if args.self_test:
        _do_self_tests(args.debug)

    if args.use_sample_code:
        if args.language == "bash":
            code = "\n".join(_SAMPLE_BASH_INSTRUCTIONS) + "\n"
        else:
            code = "\n".join(_SAMPLE_PYTHON_INSTRUCTIONS) + "\n"
    else:
        code = sys.stdin.read()

    async def _local_run():
        def _dummy_emitter(event):
            if not args.want_status:
                print(f"Event: {event}", file=sys.stderr)

        tools = Tools()
        if args.language == "bash":
            output_str = await tools.run_bash_command(
                bash_command=code, __event_emitter__=_dummy_emitter
            )
        else:
            output_str = await tools.run_python_code(
                python_code=code, __event_emitter__=_dummy_emitter
            )
        if args.want_status:
            output = json.loads(output_str)
            got_status = output["status"]
            if got_status != args.want_status:
                raise RuntimeError(
                    f"Code evaluation status is {got_status} but expected {args.want_status}"
                )
            print(
                f"\u2705 Code evaluation status is {got_status} as expected.",
                file=sys.stderr,
            )
        else:
            print(output_str)

    asyncio.run(_local_run())
