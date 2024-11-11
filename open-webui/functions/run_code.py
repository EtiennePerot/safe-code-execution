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
# This is an OpenWebUI *function*. It can run code within LLM-generated code blocks.
# If you are looking for an OpenWebUI *tool* to allow the LLM to run its own code,
# see here instead: https://openwebui.com/t/etienneperot/run_code/

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
import socket
import struct
import threading
import time
import urllib.request
import fcntl
import mimetypes
import stat
import urllib.parse
import datetime
import urllib.error


class _Action:
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
        MAX_FILES_PER_EXECUTION: int = pydantic.Field(
            ge=1,
            default=32,
            description=f"Maximum number of generated files to allow per code execution; may be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}MAX_FILES_PER_EXECUTION.",
        )
        MAX_FILES_PER_USER: int = pydantic.Field(
            ge=1,
            default=4096,
            description=f"Maximum number of files to keep around for a given user; may be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}MAX_FILES_PER_USER.",
        )
        MAX_MEGABYTES_PER_USER: int = pydantic.Field(
            ge=1,
            default=256,
            description=f"Maximum total size of files to keep around for a given user; may be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}MAX_MEGABYTES_PER_USER.",
        )
        REQUIRE_RESOURCE_LIMITING: bool = pydantic.Field(
            default=True,
            description=f"Whether to enforce resource limiting, which requires cgroups v2 to be available; may be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}REQUIRE_RESOURCE_LIMITING.",
        )
        WEB_ACCESSIBLE_DIRECTORY_PATH: str = pydantic.Field(
            default="$DATA_DIR/cache/functions/run_code",
            description=f"Path of the directory to write files that should be accessible for user download in. If it begins by '$DATA_DIR', this will be replaced with the DATA_DIR environment variable. The whole field may be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}WEB_ACCESSIBLE_DIRECTORY_PATH.",
        )
        WEB_ACCESSIBLE_DIRECTORY_URL: str = pydantic.Field(
            default="/cache/functions/run_code",
            description=f"URL corresponding to WEB_ACCESSIBLE_DIRECTORY_PATH. May start with '/' to make it relative to the Open WebUI serving domain. May be overridden by environment variable {_VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}WEB_ACCESSIBLE_DIRECTORY_URL.",
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
                elif type(valve_value) is type(""):
                    pass
                else:
                    valve_value_type = type(valve_value)
                    raise ValueError(f"Unknown valve type: {valve_value_type}")
            except Exception as e:
                raise ValueError(
                    f"Valve override {self.valves._VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX}{valve_name}={valve_value}: bad value: {e}"
                )
            else:
                setattr(self.valves, valve_name, override)

    async def action(
        self,
        body: dict,
        __event_emitter__: typing.Callable[[dict], typing.Any] = None,
        __id__: typing.Optional[str] = None,
        __user__: typing.Optional[dict] = None,
    ) -> typing.Optional[dict]:
        valves = self.valves
        debug = valves.DEBUG
        emitter = EventEmitter(__event_emitter__, debug=debug)
        execution_tracker: typing.Optional[CodeExecutionTracker] = None

        update_check_error = None
        update_check_notice = ""
        if valves.CHECK_FOR_UPDATES:
            if UpdateCheck.need_check():
                await emitter.status("Checking for updates...")
            try:
                newer_version = UpdateCheck.get_newer_version()
            except UpdateCheck.VersionCheckError as e:
                update_check_error = e
                update_check_notice = (
                    f"\n\n(Failed to check for update to code execution function: {e})"
                )
            else:
                if newer_version is not None:
                    await emitter.status(f"New version found: {newer_version}")
                    emitter.set_status_prefix(f"[Update available: {newer_version}] ")
                    update_check_notice = f"\n\n(Code execution function update available: [{newer_version}]({UpdateCheck.USER_URL}))"

        storage = UserStorage(
            storage_root_path=os.path.join(
                valves.WEB_ACCESSIBLE_DIRECTORY_PATH, "user_files"
            ),
            storage_root_url=valves.WEB_ACCESSIBLE_DIRECTORY_URL.rstrip("/")
            + "/user_files",
            __user__=__user__,
            max_files_per_user=valves.MAX_FILES_PER_USER,
            max_bytes_per_user=valves.MAX_MEGABYTES_PER_USER * 1024 * 1024,
        )

        async def _fail(error_message, status="SANDBOX_ERROR"):
            if execution_tracker is not None:
                execution_tracker.set_error(error_message)
                await emitter.code_execution(execution_tracker)
            if debug:
                await emitter.fail(
                    f"[DEBUG MODE] {error_message}; body={body}; valves=[{valves}]"
                )
            elif update_check_error is not None:
                await emitter.fail(f"[{update_check_error}] {error_message}")
            else:
                await emitter.fail(error_message)
            return json.dumps({"status": status, "output": error_message})

        if len(body.get("messages", ())) == 0:
            return await _fail("No messages in conversation.", status="INVALID_INPUT")
        last_message = body["messages"][-1]
        if last_message["role"] != "assistant":
            return await _fail(
                "Last message was not from the AI model.", status="INVALID_INPUT"
            )
        split_three_backticks = last_message["content"].split("```")
        if len(split_three_backticks) < 3:
            return await _fail(
                "Last message did not contain code blocks.", status="INVALID_INPUT"
            )
        if len(split_three_backticks) % 2 != 1:
            return await _fail(
                "Last message did not contain well-formed code blocks.",
                status="INVALID_INPUT",
            )
        chosen_code_block = None
        language = None
        for code_block in split_three_backticks[-2:0:-2]:
            if code_block.startswith("python\n") or code_block.startswith("python3\n"):
                chosen_code_block = code_block
                language = Sandbox.LANGUAGE_PYTHON
            if (
                code_block.startswith("bash\n")
                or code_block.startswith("sh\n")
                or code_block.startswith("shell\n")
            ):
                chosen_code_block = code_block
                language = Sandbox.LANGUAGE_BASH
                break
        if chosen_code_block is None:
            # Try to see if the last code block looks like Python or bash.
            last_code_block = split_three_backticks[-2]
            # Look for an interpreter line.
            first_line = last_code_block.strip().split("\n")[0]
            if first_line.startswith("#!") and (
                first_line.endswith("python") or first_line.endswith("python3")
            ):
                chosen_code_block = code_block
                language = Sandbox.LANGUAGE_PYTHON
            elif first_line.startswith("#!") and first_line.endswith("sh"):
                chosen_code_block = code_block
                language = Sandbox.LANGUAGE_BASH
            elif any(
                python_like in last_code_block
                for python_like in ("import ", "print(", "print ")
            ):
                chosen_code_block = code_block
                language = Sandbox.LANGUAGE_PYTHON
            elif any(
                bash_like in last_code_block
                for bash_like in ("echo ", "if [", "; do", "esac\n")
            ):
                chosen_code_block = code_block
                language = Sandbox.LANGUAGE_BASH
        if chosen_code_block is None:
            return await _fail(
                "Message does not contain code blocks detected as Python or Bash."
            )

        try:
            max_ram_bytes = None
            if self.valves.MAX_RAM_MEGABYTES != 0:
                max_ram_bytes = self.valves.MAX_RAM_MEGABYTES * 1024 * 1024

            Sandbox.check_setup(
                language=language,
                auto_install_allowed=self.valves.AUTO_INSTALL,
                require_resource_limiting=self.valves.REQUIRE_RESOURCE_LIMITING,
            )

            if self.valves.AUTO_INSTALL and Sandbox.runsc_needs_installation():
                await emitter.status("Auto-installing gVisor...")
                Sandbox.install_runsc()

            status = "UNKNOWN"
            output = None
            generated_files = []
            language_title = language.title()

            # If the provided code starts/ends with "```SOME_LANGUAGE", remove that.
            code = chosen_code_block
            if language == Sandbox.LANGUAGE_PYTHON:
                code = code.removeprefix("python3")
                code = code.removeprefix("python")
            elif language == Sandbox.LANGUAGE_BASH:
                code = code.removeprefix("shell")
                code = code.removeprefix("bash")
                code = code.removeprefix("sh")
            code = code.strip()
            language_title = language.title()
            execution_tracker = CodeExecutionTracker(
                name=f"{language_title} code block", code=code, language=language
            )
            await emitter.clear_status()
            await emitter.code_execution(execution_tracker)

            with tempfile.TemporaryDirectory(prefix="sandbox_") as tmp_dir:
                sandbox_storage_path = os.path.join(tmp_dir, "storage")
                os.makedirs(sandbox_storage_path, mode=0o777)

                sandbox = Sandbox(
                    tmp_dir=tmp_dir,
                    snippets=((language, code),),
                    debug=debug,
                    networking_allowed=valves.NETWORKING_ALLOWED,
                    max_runtime_seconds=valves.MAX_RUNTIME_SECONDS,
                    max_ram_bytes=max_ram_bytes,
                    require_resource_limiting=valves.REQUIRE_RESOURCE_LIMITING,
                    persistent_home_dir=sandbox_storage_path,
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
                    output_num_files, _ = storage.measure_directory(
                        sandbox_storage_path
                    )
                    if output_num_files > valves.MAX_FILES_PER_EXECUTION:
                        output = f"Code produced {output_num_files} files, exceeding per-execution quota of {valves.MAX_FILES_PER_EXECUTION}"
                        await emitter.fail(output)
                        status = "STORAGE_ERROR"
                    elif output_num_files > 0:
                        try:
                            with storage:
                                generated_files = storage.copy(
                                    __id__=__id__,
                                    intake_path=sandbox_storage_path,
                                )
                        except UserStorage.OutOfStorageException as e:
                            status = "STORAGE_ERROR"
                            output = f"Storage quota exceeded: {e}"
                            await emitter.fail(output)
                        for generated_file in generated_files:
                            execution_tracker.add_file(
                                name=generated_file.name, url=generated_file.url
                            )
                if output:
                    output = output.strip()
                execution_tracker.set_output(output)
                await emitter.code_execution(execution_tracker)
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
            if status == "OK":
                generated_files_output = ""
                if len(generated_files) > 0:
                    generated_files_output = "* " + "\n* ".join(
                        f.markdown()
                        for f in sorted(generated_files, key=lambda f: f.name)
                    )
                if output and len(generated_files) > 0:
                    await emitter.message(
                        f"\n\n---\nI executed this {language_title} code and got:\n```Output\n{output}\n```\n**Files**:\n{generated_files_output}{update_check_notice}"
                    )
                elif output and len(generated_files) == 0:
                    await emitter.message(
                        f"\n\n---\nI executed this {language_title} code and got:\n```Output\n{output}\n```{update_check_notice}"
                    )
                elif len(generated_files) > 0:
                    await emitter.message(
                        f"\n\n---\nI executed this {language_title} code and it generated these files:\n{generated_files_output}{update_check_notice}"
                    )
                else:
                    await emitter.message(
                        f"\n\n---\nI executed this {language_title} code and it ran successfully with no output.{update_check_notice}"
                    )
                return json.dumps(
                    {
                        "status": status,
                        "output": output,
                        "generated_files": {
                            f.name: f.markdown() for f in generated_files
                        },
                    }
                )
            if status == "TIMEOUT":
                if output:
                    await emitter.message(
                        f"\n\n---\nI executed this {language_title} code and it timed out after {self.valves.MAX_RUNTIME_SECONDS} seconds:\n```Error\n{output}\n```\n{update_check_notice}"
                    )
                else:
                    await emitter.message(
                        f"\n\n---\nI executed this {language_title} code and it timed out after {self.valves.MAX_RUNTIME_SECONDS} seconds.\n{update_check_notice}"
                    )
            elif status == "INTERRUPTED":
                if output:
                    await emitter.message(
                        f"\n\n---\nI executed this {language_title} code and used too many resources.\n```Error\n{output}\n```\n{update_check_notice}"
                    )
                else:
                    await emitter.message(
                        f"\n\n---\nI executed this {language_title} code and used too many resources.\n{update_check_notice}"
                    )
            elif status == "STORAGE_ERROR":
                await emitter.message(
                    f"\n\n---\nI executed this {language_title} code but it exceeded the storage quota.\n```Error\n{output}\n```\n{update_check_notice}"
                )
            elif status == "ERROR" and output:
                await emitter.message(
                    f"\n\n---\nI executed this {language_title} code and got the following error:\n```Error\n{output}\n```\n{update_check_notice}"
                )
            elif status == "ERROR":
                await emitter.message(
                    f"\n\n---\nI executed this {language_title} code but got an unexplained error.\n{update_check_notice}"
                )
            else:
                raise Sandbox.SandboxRuntimeException(
                    f"Unexplained status: {status} (output: {output})"
                )
            return json.dumps({"status": status, "output": output})
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


class Action:
    Valves = _Action.Valves

    def __init__(self):
        self.valves = self.Valves()

    async def action(
        self,
        body: dict,
        __event_emitter__: typing.Callable[[dict], typing.Any] = None,
    ) -> typing.Optional[dict]:
        return await _Action(self.valves).action(
            body=body, __event_emitter__=__event_emitter__
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
            "id": self._uuid,
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
        "/proc/sys/kernel/unprivileged_userns_clone",
        "/proc/sys/kernel/unprivileged_userns_apparmor_policy",
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
    _STAGE_SERVER = "SERVER"

    # Timeout slack in max runtime enforcement, from deepest to shallowest.
    _TIMEOUT_SLACK_FINAL = 0.25  # Actual code execution
    _TIMEOUT_SLACK_CONNECT = (
        _TIMEOUT_SLACK_FINAL + 0.5
    )  # Connect to code evaluation server
    _TIMEOUT_SLACK_CONNECT_FIRST_REQUEST = (
        _TIMEOUT_SLACK_FINAL + 5
    )  # Connect to code evaluation server for first request
    _TIMEOUT_SLACK_CODE_EVAL_REQUEST = (
        _TIMEOUT_SLACK_CONNECT + 2.0
    )  # Send and receive code evaluation request data
    _TIMEOUT_SLACK_COPY_OUT = (
        _TIMEOUT_SLACK_FINAL + 5
    )  # Copy files from persistent directory
    _TIMEOUT_SLACK_TERMINATE = (
        _TIMEOUT_SLACK_FINAL + 0.5
    )  # Terminate code evaluation server
    _TIMEOUT_SLACK_WAIT_FOR_SANDBOX_SHUTDOWN = (
        _TIMEOUT_SLACK_FINAL + 1
    )  # Wait for sandbox process to exit.

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
            self._my_uids = None
            self._my_gids = None
            self._initial_status_data = None
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
                ("save_proc_self_status", self._save_proc_self_status),
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

        def _read_proc_self_status(self):
            """Read /proc/self/status and return some of it as a dictionary."""
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
            status_data = {}
            with self._open("/proc/self/status", "rb") as status_f:
                for line in status_f.read().decode("utf-8").splitlines():
                    for header in want_headers:
                        if line.startswith(f"{header}:"):
                            status_data[header] = line.split(":")[1].strip()
                            break
            return status_data

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
            status_line = f"{main_status} (uids={self._my_uids} gids={self._my_gids} pid={my_pid} initial_proc_self_status={self._initial_status_data} do_resource_limiting={self._do_resource_limiting} initial_cgroup_name={self._initial_cgroup_name} codeeval_cgroup_name={self._codeeval_cgroup_name} controllers={self._cgroup_controllers})"
            try:
                status_data = self._read_proc_self_status()
            except OSError as e:
                status_line += f" (error parsing /proc/self/status: {e})"
            else:
                for header, value in status_data.items():
                    status_line += f" {header}={value}"
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
            self._my_uids = os.getresuid()

        def _save_egid(self):
            self._my_gids = os.getresgid()

        def _save_proc_self_status(self):
            self._initial_status_data = self._read_proc_self_status()

        def _unshare_user(self):
            Sandbox.unshare(
                os.CLONE_NEWUSER if "CLONE_NEWUSER" in os.__dict__ else 0x10000000
            )

        def _write_uid_map(self):
            with self._open("/proc/self/uid_map", "wb") as uid_map_f:
                uid_map_f.write(f"0 {self._my_uids[1]} 1\n".encode("ascii"))

        def _write_setgroups(self):
            with self._open("/proc/self/setgroups", "wb") as setgroups_f:
                setgroups_f.write(b"deny")

        def _write_gid_map(self):
            with self._open("/proc/self/gid_map", "wb") as gid_map_f:
                gid_map_f.write(f"0 {self._my_gids[1]} 1\n".encode("ascii"))

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

    class _InSandboxServer:
        """
        Server that runs inside the gVisor sandbox.
        """

        def __init__(self):
            pass

        def run(self):
            """
            Run a server loop inside the server listening on UDS.
            This code is called from *within* the gVisor sandbox.
            """
            keep_going = True
            server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server_socket.bind("/sandbox/socket")
            server_socket.listen(1)
            server_socket_closed = False
            try:
                with open("/sandbox/started", "wb") as started_f:
                    started_f.write(b"OK\n")
                while keep_going:
                    client_socket, _ = server_socket.accept()
                    try:
                        request_size_buf = client_socket.recv(8)
                        if len(request_size_buf) != 8:
                            raise Sandbox.SandboxRuntimeException(
                                f"Server did not receive 8 bytes for request size: {repr(request_size_buf)}"
                            )
                        request_length = struct.unpack(">Q", request_size_buf)[0]
                        request_bytes = []
                        remaining_bytes = request_length
                        while remaining_bytes > 0:
                            packet_size = min(remaining_bytes, 0x100000)
                            request_data = client_socket.recv(packet_size)
                            if len(request_data) == 0:
                                break
                            remaining_bytes -= len(request_data)
                            request_bytes.append(request_data)
                        if remaining_bytes > 0:
                            raise Sandbox.SandboxRuntimeException(
                                f"Got partial request; {remaining_bytes}/{request_length} bytes still expected"
                            )
                        request_data = json.loads(
                            (b"".join(request_bytes)).decode("utf-8")
                        )
                        if "type" not in request_data or "kwargs" not in request_data:
                            raise Sandbox.SandboxRuntimeException(
                                f"Invalid request to in-sandbox server: {request_data}"
                            )
                        request_type = request_data["type"]
                        request_kwargs = request_data.get("kwargs", {})
                        response = None
                        if request_type == "code_eval":
                            response = self._handle_code_eval(**request_kwargs)
                        elif request_type == "copy_out":
                            response = self._handle_copy_out(**request_kwargs)
                        elif request_type == "terminate":
                            keep_going = False
                            server_socket.close()
                            server_socket_closed = True
                            response = {}
                        else:
                            raise Sandbox.SandboxRuntimeException(
                                f"Invalid request type: {request_type}"
                            )
                    except Exception as e:
                        response = {"exception": Sandbox._json_exception_encode(e)}
                    assert response is not None, "Logic error"
                    try:
                        response_bytes = json.dumps(response).encode("utf-8")
                        client_socket.sendall(struct.pack(">Q", len(response_bytes)))
                        client_socket.sendall(response_bytes)
                    finally:
                        client_socket.close()
            finally:
                if not server_socket_closed:
                    server_socket.close()

        def _handle_code_eval(self, language, code, max_runtime_seconds):
            """
            Handle a single code evaluation request.
            """
            if language not in Sandbox.SUPPORTED_LANGUAGES:
                raise Sandbox.SandboxRuntimeException(
                    f"Unsupported language: {language}"
                )
            interpreter_path = None
            if language == Sandbox.LANGUAGE_BASH:
                interpreter_path = shutil.which("bash")
            elif language == Sandbox.LANGUAGE_PYTHON:
                interpreter_path = sys.executable
            if interpreter_path is None:
                raise Sandbox.SandboxRuntimeException(
                    f"Cannot find interpreter for language: {language}"
                )
            cmd = [interpreter_path, "/dev/stdin"]
            if max_runtime_seconds <= 0.0:
                raise Sandbox.SandboxRuntimeException(
                    "Exceeded the code execution deadline"
                )
            try:
                result = subprocess.run(
                    cmd,
                    input=code + "\n",
                    text=True,
                    capture_output=True,
                    timeout=max_runtime_seconds + Sandbox._TIMEOUT_SLACK_FINAL,
                    check=True,
                )
            except subprocess.TimeoutExpired as e:
                raise Sandbox.ExecutionTimeoutError(
                    code=code,
                    returncode=126,
                    cmd=cmd,
                    output=e.stdout or "",
                    stderr=e.stderr or "",
                )
            except subprocess.CalledProcessError as e:
                raise Sandbox.CodeExecutionError(
                    code=code,
                    returncode=e.returncode,
                    cmd=cmd,
                    output=e.stdout or "",
                    stderr=e.stderr or "",
                )
            else:
                return {
                    "args": cmd,
                    "returncode": 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }

        def _handle_copy_out(self):
            if os.path.isdir("/sandbox/persistent"):
                shutil.copytree(
                    "/home/user",
                    "/sandbox/persistent",
                    ignore_dangling_symlinks=True,
                    dirs_exist_ok=True,
                )
            return {}

    class _SandboxClient:
        """
        Client counterpart to `_InSandboxServer`.
        This runs outside of the gVisor sandbox.
        """

        class _RequestTimeoutError(Exception):
            """Raised when _request takes too long."""

        class _ServerDiedError(Exception):
            """Raised when the server dies mid-request."""

        def __init__(self, sandbox_shared_path, runsc_popen):
            """
            Constructor.

            :param sandbox_shared_path: Path to the dir mounted as /sandbox in the sandbox.
            :param runsc_popen: subprocess.Popen object to runsc, to check for liveness.
            """
            self._sandbox_shared_path = sandbox_shared_path
            self._runsc_popen = runsc_popen
            self._first_request = True

        def _check_server_alive(self):
            """Check if the server is alive.

            :return: True if the server is still alive.
            :raises _ServerDiedError: If the server is not alive.
            """
            try:
                self._runsc_popen.wait(timeout=Sandbox._TIMEOUT_SLACK_CONNECT)
            except subprocess.TimeoutExpired:
                return True
            else:
                raise self._ServerDiedError()

        def _request(self, request_type, deadline, **request_kwargs):
            """Connect and get a socket to the server."""
            if self._first_request:
                connect_deadline = min(
                    deadline, time.time() + Sandbox._TIMEOUT_SLACK_CONNECT_FIRST_REQUEST
                )
                self._first_request = False
            else:
                connect_deadline = min(
                    deadline, time.time() + Sandbox._TIMEOUT_SLACK_CONNECT
                )
            started_marker_path = os.path.join(self._sandbox_shared_path, "started")
            while time.time() < connect_deadline and not os.path.exists(
                started_marker_path
            ):
                time.sleep(0.05)
            if time.time() >= connect_deadline and not os.path.exists(
                started_marker_path
            ):
                raise Sandbox.SandboxRuntimeException(
                    f"Sandbox did not start in time: {started_marker_path} still does not exist"
                )
            client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            socket_path = os.path.join(self._sandbox_shared_path, "socket")
            try:
                client_socket.connect(socket_path)
            except Exception as e:
                raise Sandbox.SandboxRuntimeException(
                    f"Cannot connect to socket at {socket_path}: {e}"
                )
            try:
                client_socket.settimeout(0.5)
                request_bytes = json.dumps(
                    {
                        "type": request_type,
                        "kwargs": request_kwargs,
                    }
                ).encode("utf-8")
                client_socket.sendall(struct.pack(">Q", len(request_bytes)))
                client_socket.sendall(request_bytes)
                response_size = None
                remaining_bytes = -1
                response_bytes = []
                while (
                    response_size is None or remaining_bytes > 0
                ) and time.time() < deadline:
                    try:
                        if response_size is None:
                            response_size_buf = client_socket.recv(8)
                            if len(response_size_buf) != 8:
                                self._check_server_alive()
                                raise Sandbox.SandboxRuntimeException(
                                    f"Client did not get 8 bytes for response size: {repr(response_size_buf)}"
                                )
                            response_size = struct.unpack(">Q", response_size_buf)[0]
                            remaining_bytes = response_size
                        if remaining_bytes > 0:
                            packet_data = client_socket.recv(
                                min(remaining_bytes, 0x100000)
                            )
                            if len(packet_data) == 0:
                                self._check_server_alive()
                                break
                            remaining_bytes -= len(packet_data)
                            response_bytes.append(packet_data)
                    except socket.timeout:
                        continue
                if time.time() >= deadline:
                    self._check_server_alive()
                    raise self._RequestTimeoutError()
                try:
                    response = json.loads((b"".join(response_bytes)).decode("utf-8"))
                except json.decoder.JSONDecodeError as e:
                    raise Sandbox.SandboxRuntimeException(
                        f"Invalid response JSON: {e} ({repr(response_bytes)})"
                    )
                if "exception" in response:
                    raise Sandbox._json_exception_decode(response["exception"])
                return response
            finally:
                client_socket.close()

        def code_eval(
            self, language, code, max_runtime_seconds
        ) -> subprocess.CompletedProcess:
            """Run a single snippet of code."""
            request_deadline = (
                time.time()
                + max_runtime_seconds
                + Sandbox._TIMEOUT_SLACK_CODE_EVAL_REQUEST
            )
            try:
                response = self._request(
                    "code_eval",
                    request_deadline,
                    language=language,
                    code=code,
                    max_runtime_seconds=max_runtime_seconds,
                )
            except self._RequestTimeoutError:
                raise Sandbox.ExecutionTimeoutError(
                    code=code,
                    returncode=126,
                    cmd=[language],
                    output=None,
                    stderr=None,
                )
            except self._ServerDiedError:
                raise Sandbox.InterruptedExecutionError(
                    code=code,
                    returncode=127,
                    cmd=[language],
                    output=None,
                    stderr=None,
                )
            else:
                return subprocess.CompletedProcess(
                    args=response["args"],
                    returncode=response["returncode"],
                    stdout=response.get("stdout"),
                    stderr=response.get("stderr"),
                )

        def copy_out(self):
            self._request("copy_out", time.time() + Sandbox._TIMEOUT_SLACK_COPY_OUT)

        def terminate(self):
            self._request("terminate", time.time() + Sandbox._TIMEOUT_SLACK_TERMINATE)

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
    def _json_exception_encode(cls, e):
        exception_info = {
            "name": e.__class__.__name__,
            "str": str(e),
        }
        if isinstance(e, cls.SandboxException) or isinstance(e, cls.ExecutionError):
            exception_info["args"] = e._sandbox_exception_args
            exception_info["kwargs"] = e._sandbox_exception_kwargs
        return exception_info

    @classmethod
    def _json_exception_decode(cls, exception_data):
        """Returns a JSON-encoded exception."""
        class_name = exception_data["name"]
        found_class = None
        for ex_class in (
            cls.PlatformNotSupportedException,
            cls.SandboxRuntimeException,
            cls.CodeExecutionError,
            cls.ExecutionTimeoutError,
            cls.InterruptedExecutionError,
            cls.GVisorNotInstalledException,
            cls.CorruptDownloadException,
            cls.EnvironmentNeedsSetupException,
            cls.ExecutionError,
            cls.SandboxException,
        ):
            if ex_class.__name__ == class_name:
                found_class = ex_class
                break
        if found_class is None:
            exception_str = exception_data["str"]
            return cls.SandboxRuntimeException(f"{class_name}: {exception_str}")
        return found_class(*exception_data["args"], **exception_data["kwargs"])

    @classmethod
    def _json_completed_process_decode(cls, result) -> subprocess.CompletedProcess:
        """Decode a JSON-encoded subprocess.CompletedProcess."""
        stdout = None
        if result["stdout"] is not None:
            stdout = base64.b64decode(result["stdout"])
            if result["stdout_is_text"]:
                stdout = stdout.decode("utf-8", errors="replace")
        stderr = None
        if result["stderr"] is not None:
            stderr = base64.b64decode(result["stderr"])
            if result["stderr_is_text"]:
                stderr = stderr.decode("utf-8", errors="replace")
        return subprocess.CompletedProcess(
            args=result["args"],
            returncode=result["returncode"],
            stdout=stdout,
            stderr=stderr,
        )

    @classmethod
    def _json_completed_process_encode(cls, result: subprocess.CompletedProcess):
        """Return a JSON-encoded subprocess.CompletedProcess."""
        stdout = result.stdout
        stdout_is_text = False
        if stdout is not None and type(stdout) is not type(b""):
            stdout = stdout.encode("utf-8", errors="replace")
            stdout_is_text = True
        stderr = result.stderr
        stderr_is_text = False
        if stderr is not None and type(stderr) is not type(b""):
            stderr = stderr.encode("utf-8", errors="replace")
            stderr_is_text = True
        return {
            "args": result.args,
            "returncode": result.returncode,
            "stdout": base64.b64encode(stdout).decode("utf-8")
            if stdout is not None
            else None,
            "stdout_is_text": stdout_is_text,
            "stderr": base64.b64encode(stderr).decode("utf-8")
            if stderr is not None
            else None,
            "stderr_is_text": stderr_is_text,
        }

    @classmethod
    def _concatenate_outputs(cls, streams, encoding="utf-8"):
        """
        Concatenate a list of byte or unicode strings to a single string.
        Useful for merging stdout/stderr from multiple invocations.
        """
        is_all_text = True
        all_text = []
        for stream in streams:
            if stream is None:
                continue
            if type(stream) is type(""):
                all_text.append(stream)
            elif type(stream) is type(b""):
                try:
                    text_stream = stream.decode(encoding, errors="strict")
                except UnicodeDecodeError:
                    is_all_text = False
                    break
                else:
                    all_text.append(text_stream)
            else:
                raise cls.SandboxRuntimeException(
                    f"Non-string passed to _concatenate_outputs: {type(stream)}"
                )
        if is_all_text:
            return "".join(all_text)
        all_bytes = []
        for stream in streams:
            if stream is None:
                continue
            if type(stream) is type(b""):
                all_bytes.append(stream)
            elif type(stream) is type(""):
                all_bytes.append(stream.encode(encoding, errors="strict"))
            else:
                assert False, "Logic error"
        return b"".join(all_bytes)

    @classmethod
    def _process_json_wrapped_result(
        cls, result: subprocess.CompletedProcess
    ) -> subprocess.CompletedProcess:
        """
        Process a `CompletedProcess` from a wrapped invocation.

        :param result: A `CompletedProcess` with stdout captured.
        :return: A synthetic `CompletedProcess` from the JSON information in stdout.
        :raises Sandbox.SandboxRuntimeException: If the JSON information cannot be interpreted.
        :raises Sandbox.SandboxException: For any exception that is forwarded.
        """
        if not result.stdout:
            raise cls.SandboxRuntimeException(
                f"Subprocess interpreter did not produce any output (stderr: {result.stderr})"
            )
        try:
            output = json.loads(result.stdout)
        except json.decoder.JSONDecodeError as e:
            raise cls.SandboxRuntimeException(
                f"Invalid process JSON data (stdout: {result.stdout}): {e}"
            )
        if "exception" in output:
            raise cls._json_exception_decode(output["exception"])
        if "result" not in output:
            raise cls.SandboxRuntimeException(
                f"Invalid response from subprocess: {output}"
            )
        return cls._json_completed_process_decode(output["result"])

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
        result = None
        output_stream = sys.stderr
        try:
            directives = json.load(sys.stdin)
            sandbox = cls(**directives["settings"])
            if directives["stage"] == cls._STAGE_SANDBOX:
                output_stream = sys.stdout
                result = cls._json_completed_process_encode(sandbox._run())
            elif directives["stage"] == cls._STAGE_SERVER:
                cls._InSandboxServer().run()
                result = {}
            else:
                raise ValueError(f"Invalid stage in directives: {directives}")
        except Exception as e:
            json.dump({"exception": cls._json_exception_encode(e)}, output_stream)
        else:
            assert result is not None, "Logic error"
            json.dump({"result": result}, output_stream)
        finally:
            output_stream.flush()
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

    def _run(self) -> subprocess.CompletedProcess:
        """
        Spawn and wait for the sandbox. Runs in separate forked process.

        :return: A `CompletedProcess` object representing the return code and stdout/stderr of the code interpreter.
        :raises Sandbox.SandboxRuntimeException: If the sandbox failed to start or behaved incorrectly regardless of the code being evaluated.
        :raises Sandbox.ExecutionTimeoutError: If the code interpreter ran for longer than configured.
        :raises Sandbox.InterruptedExecutionError: If the code interpreter died without providing a return code; usually due to running over resource limits.
        :raises sandbox.CodeExecutionError: If the code interpreter failed to execute the given code. This does not represent a sandbox failure.
        """
        runsc = None
        resource_monitor_cancel = None
        runsc_memfd_stdout = None
        runsc_memfd_stderr = None
        try:
            self._setup_sandbox()
            network_mode = "host" if self._networking_allowed else "none"
            runsc_argv = [
                self.get_runsc_path(),
                "--rootless=true",
                "--directfs=false",
                f"--network={network_mode}",
                "--host-uds=all",
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
                    "stage": self._STAGE_SERVER,
                    "settings": self._settings,
                }
            )
            started_marker_path = os.path.join(self._sandbox_shared_path, "started")
            resource_monitor_cancel = self._switcheroo.monitor_cgroup_resources()
            memfd_uuid = str(uuid.uuid4())
            runsc_memfd_stdout = os.fdopen(
                os.memfd_create(f"runsc-stdout.{memfd_uuid}"), "wb+"
            )
            runsc_memfd_stderr = os.fdopen(
                os.memfd_create(f"runsc-stderr.{memfd_uuid}"), "wb+"
            )
            try:
                runsc = subprocess.Popen(
                    runsc_argv,
                    env=runsc_env,
                    preexec_fn=self._switcheroo.move_process_to_sandbox_leaf_cgroup_lambda(),
                    stdin=subprocess.PIPE,
                    stdout=runsc_memfd_stdout,
                    stderr=runsc_memfd_stderr,
                    text=True,
                )
                runsc.stdin.write(runsc_input)
                runsc.stdin.close()
            except OSError as e:
                raise self.SandboxRuntimeException(f"Spawn runsc: OSError: {e}")
            except Exception as e:
                raise self.SandboxRuntimeException(f"Spawn runsc: {e}")
            sandbox_client = self._SandboxClient(
                sandbox_shared_path=self._sandbox_shared_path, runsc_popen=runsc
            )
            overall_deadline = time.time() + self._max_runtime_seconds
            overall_cmd = []
            overall_code = []
            overall_stdout = []
            overall_stderr = []
            for language, code in self._snippets:
                overall_cmd.append(f"{language} /dev/stdin")
                if len(self._snippets) == 1:
                    overall_code = [code]
                else:
                    overall_code.append(f"({language}, {code})")
                seconds_remaining = overall_deadline - time.time()
                result = sandbox_client.code_eval(
                    language=language,
                    code=code,
                    max_runtime_seconds=seconds_remaining,
                )
                if result.stdout is not None:
                    overall_stdout.append(result.stdout)
                if result.stderr is not None:
                    overall_stderr.append(result.stderr)
            overall_stdout = self._concatenate_outputs(overall_stdout)
            overall_stderr = self._concatenate_outputs(overall_stderr)
            sandbox_client.copy_out()
            sandbox_client.terminate()
            runsc_stdout = None
            runsc_stderr = None
            try:
                runsc.wait(timeout=self._TIMEOUT_SLACK_WAIT_FOR_SANDBOX_SHUTDOWN)
            except subprocess.TimeoutExpired:
                try:
                    runsc.kill()
                    runsc.wait(timeout=self._TIMEOUT_SLACK_WAIT_FOR_SANDBOX_SHUTDOWN)
                except Exception:
                    pass
            if runsc.poll() is None:
                raise self.SandboxRuntimeException("Sandbox did not terminate")
            if runsc.returncode != 0:
                if os.path.isfile(started_marker_path):
                    raise self.InterruptedExecutionError(
                        code="; ".join(overall_code),
                        returncode=127,
                        cmd=self._sandboxed_command,
                        output=overall_stdout,
                        stderr=overall_stderr,
                    )
                logs = {}

                def process_log(filename, log_line):
                    if (
                        self._debug
                        or not filename.endswith(".txt")  # Not a gVisor log file
                        or (  # gVisor log file
                            log_line
                            and log_line[0] in "WEF"  # WEF: Warning, Error, Fatal
                        )
                    ):
                        if filename not in logs:
                            logs[filename] = []
                        logs[filename].append(log_line)

                self.debug_logs(process_log)
                json_logs = json.dumps(logs)
                try:
                    runsc_memfd_stdout.seek(0)
                    runsc_stdout = runsc_memfd_stdout.read()
                    runsc_memfd_stderr.seek(0)
                    runsc_stderr = runsc_memfd_stderr.read()
                    runsc_output = (
                        (runsc_stdout + runsc_stderr)
                        .strip()
                        .decode("utf-8", errors="ignore")
                    )
                except Exception as e:
                    runsc_output = f"[cannot get output: {e}]"
                if self._debug:
                    raise self.SandboxRuntimeException(
                        f"Sandbox failed to start: {runsc.returncode}; runsc: {runsc_output}; logs: {json_logs}"
                    )
                raise self.SandboxRuntimeException(
                    f"Sandbox failed to start: {runsc.returncode}; (turn on debug mode to see more information); runsc: {runsc_output}; logs: {json_logs}"
                )
            if not os.path.isfile(started_marker_path):
                raise self.SandboxRuntimeException("Sandbox failed to start up")
            if len(overall_cmd) == 1:
                overall_args = overall_cmd[0]
            else:
                overall_args = ["sh", "-c", "; ".join(overall_cmd)]
            return subprocess.CompletedProcess(
                args=overall_args,
                returncode=0,
                stdout=overall_stdout,
                stderr=overall_stderr,
            )
        finally:
            if runsc_memfd_stdout is not None:
                runsc_memfd_stdout.close()
            if runsc_memfd_stderr is not None:
                runsc_memfd_stderr.close()
            if resource_monitor_cancel is not None:
                resource_monitor_cancel()
            if runsc is not None:
                try:
                    runsc.kill()
                    try:
                        runsc.wait(timeout=0.1)
                    except Exception:
                        pass
                except Exception:
                    pass
            if self._switcheroo is not None:
                self._switcheroo.cleanup()

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


class UserStorage:
    class StorageException(Exception):
        """Base class for storage-related exceptions."""

    class OutOfStorageException(Exception):
        """Not enough files or bytes quota."""

    class EnvironmentNeedsSetupException(Exception):
        """Storage is badly configured."""

    # Number of zeroes to use in nonces (in per-day storage directories).
    # This effectively limits the number of nonces usable in a given day.
    NUM_NONCE_ZEROS = 4

    # Free space buffer to keep free on the underlying storage device,
    # rather than allowing user storage to fill it to the brim.
    MUST_KEEP_FREE_MARGIN_MEGABYTES = 512

    class File:
        MAX_INLINE_URL_SIZE = 0
        MAX_INLINE_TEXT_LINES = 128
        MAX_INLINE_TEXT_BYTES = 65535

        def __init__(self, file_path, file_relative_path, file_url, file_size):
            self._file_path = file_path
            self._file_relative_path = file_relative_path
            self._file_url = file_url
            self._size_bytes = file_size
            mimetypes.init()
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type, _ = mimetypes.guess_type(file_url)
            if mime_type is None:
                # Check if the file is valid UTF-8 text.
                is_utf8 = True
                is_empty = True
                with open(self._file_path, "rb") as f:
                    for line in f:
                        is_empty = is_empty or len(line) > 0
                        try:
                            line.decode("utf-8")
                        except UnicodeDecodeError:
                            is_utf8 = False
                mime_type = (
                    "text/plain"
                    if (is_utf8 and not is_empty)
                    else "application/octet-stream"
                )
            self._mime_type = mime_type
            self._cached_markdown = None

        @property
        def name(self):
            return self._file_relative_path

        @property
        def url(self):
            if self._size_bytes > 0 and self._size_bytes <= self.MAX_INLINE_URL_SIZE:
                # Try to use an inline URL.
                with open(self._file_path, "rb") as f:
                    contents = f.read()
                inline_url = f"data:{self._mime_type}," + urllib.parse.quote_from_bytes(
                    contents
                )
                inline_base64 = (
                    f"data:{self._mime_type};base64,"
                    + base64.standard_b64encode(contents).decode("ascii")
                )
                shortest_url = (
                    inline_url
                    if len(inline_url) < len(inline_base64)
                    else inline_base64
                )
                if len(shortest_url) <= self.MAX_INLINE_URL_SIZE:
                    return shortest_url
            return self._file_url

        def _inline_markdown(self):
            """Render the file as inline text or markdown if small enough; otherwise return None."""
            if self._size_bytes > self.MAX_INLINE_TEXT_BYTES:
                return None
            if self._mime_type.startswith("image/"):
                return f"\U0001f5bc [{self.name}]({self.url}):  \n![{self.name}]({self.url})"
            if not self._mime_type.startswith("text/"):
                return None
            with open(self._file_path, "rb") as f:
                try:
                    contents = f.read().decode("utf-8")
                except UnicodeDecodeError:
                    return None
            lines = contents.split("\n")
            if len(lines) > self.MAX_INLINE_TEXT_LINES:
                return None
            if self._mime_type != "text/markdown":
                if "```" in contents:
                    return None
                if contents and contents[-1] == "\n":
                    contents = contents[:-1]
                return f"\U0001f4c4 [{self.name}]({self.url}):\n```\n{contents}\n```"
            components = [f"\U0001f4c3 [{self.name}]({self.url}):"]
            for line in lines:
                components.append(f"> {line}")
            if components[-1] == "> ":
                components = components[:-1]
            return "\n".join(components)

        def _markdown(self):
            if self._size_bytes == 0:
                return f"\u2049 `{self.name}` (empty)"
            inline_markdown = self._inline_markdown()
            if inline_markdown is not None:
                return inline_markdown
            icon = "\U0001f4be"
            if self._mime_type.startswith("text/"):
                icon = "\U0001f4c4"
            elif self._mime_type.startswith("image/"):
                icon = "\U0001f5bc"
            elif self._mime_type.startswith("audio/"):
                icon = "\U0001f3b5"
            elif self._mime_type.startswith("video/"):
                icon = "\U0001f3ac"
            size = f"{self._size_bytes} bytes"
            if self._size_bytes > 1024 * 1024 * 1024:
                size = f"{self._size_bytes // 1024 // 1024 // 1024} GiB"
            elif self._size_bytes > 1024 * 1024:
                size = f"{self._size_bytes // 1024 // 1024} MiB"
            elif self._size_bytes > 1024:
                size = f"{self._size_bytes // 1024} KiB"
            return f"{icon} [{self.name}]({self.url}) ({size})"

        def markdown(self):
            if self._cached_markdown is None:
                self._cached_markdown = self._markdown()
            return self._cached_markdown

    @classmethod
    def measure_directory(cls, path, predicate=None):
        """
        Measure storage cost of a directory.

        :param path: Path to the directory to measure.
        :param predicate: Optional predicate to filter files and directories, called with absolute paths.
        :return: 2-tuple `(total_files, total_bytes)`. Note that `total_files` counts the number of non-root directories as well, and `total_bytes` also includes storage necessary to store filenames and directory names.
        """
        path = os.path.normpath(os.path.abspath(path))
        total_files = 0
        total_bytes = 0
        try:
            for dirpath, subdirs, subfiles in os.walk(
                path, onerror=None, followlinks=False
            ):
                dirpath = os.path.normpath(os.path.abspath(dirpath))
                for subdir in subdirs:
                    if predicate is None or predicate(os.path.join(dirpath, subdir)):
                        total_files += 1
                        total_bytes += len(subdir)
                for subfile in subfiles:
                    subfile_path = os.path.join(dirpath, subfile)
                    if predicate is not None and not predicate(subfile_path):
                        continue
                    try:
                        subfile_stat = os.stat(subfile_path, follow_symlinks=False)
                    except FileNotFoundError:
                        continue  # Likely raced with another execution.
                    if not stat.S_ISREG(subfile_stat.st_mode):
                        continue  # Ignore non-regular files.
                    total_files += 1
                    total_bytes += len(subfile)
                    total_bytes += subfile_stat.st_size
        except OSError as e:
            raise cls.EnvironmentNeedsSetupException(
                f"Failed to explore directory {path} (please adjust permissions): {e}"
            )
        return total_files, total_bytes

    def __init__(
        self,
        storage_root_path,
        storage_root_url,
        __user__: typing.Optional[dict] = None,
        max_files_per_user=None,
        max_bytes_per_user=None,
    ):
        if storage_root_path.startswith("$DATA_DIR" + os.sep):
            if "DATA_DIR" not in os.environ:
                data_dir = "/app/backend/data"
                if not os.path.isdir(data_dir):
                    if os.path.isdir("/app/backend"):
                        os.makedirs(data_dir, mode=0o755)
                    else:
                        raise self.EnvironmentNeedsSetupException(
                            f"DATA_DIR specified in user storage configuration ({storage_root_path}), but not specified in environment, and default path '/app/backend/data' does not exist; please create it or configure user storage directory."
                        )
            else:
                data_dir = os.environ["DATA_DIR"]
            storage_root_path = os.path.join(
                data_dir,
                storage_root_path[len("$DATA_DIR" + os.sep) :].lstrip(os.sep),
            )
        self._storage_root_path = os.path.normpath(os.path.abspath(storage_root_path))
        try:
            os.makedirs(self._storage_root_path, mode=0o755, exist_ok=True)
        except OSError as e:
            raise self.EnvironmentNeedsSetupException(
                f"User storage directory ({self._storage_root_path}) does not exist and cannot automatically create it ({e}); please create it or reconfigure it."
            )
        self._storage_root_url = storage_root_url.rstrip("/")
        self._date = time.strftime("%Y/%m/%d")
        self._max_files_per_user = max_files_per_user
        self._max_bytes_per_user = max_bytes_per_user
        self._user = f"anon_{self._date}"
        if __user__ is not None:
            if type(__user__) is type({}):
                self._user = str(
                    "|".join(
                        f"{k}={v}"
                        for k, v in sorted(__user__.items(), key=lambda x: x[0])
                    )
                )
            else:
                self._user = str(__user__)
        user_hash = hashlib.sha512()
        user_hash.update(self._user.encode("utf-8"))
        self._user_hash = (
            base64.b32encode(user_hash.digest()).decode("ascii").lower()[:12]
        )
        self._user_path = os.path.join(storage_root_path, self._user_hash)
        self._lock_fd = None

    def __enter__(self):
        assert self._lock_fd is None
        os.makedirs(self._user_path, mode=0o755, exist_ok=True)
        lock_fd = os.open(
            os.path.join(self._user_path, ".lock"),
            os.O_RDWR | os.O_CREAT | os.O_TRUNC,
        )
        deadline = time.time() + 10
        last_exception = None
        while time.time() < deadline:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (IOError, OSError) as e:
                last_exception = e
                time.sleep(0.01)
            else:
                self._lock_fd = lock_fd
                break
        if self._lock_fd is None:
            os.close(lock_fd)
            raise self.StorageException(
                f"Cannot lock storage directory (too many concurrent code executions?) {last_exception}"
            )

    def __exit__(self, *args, **kwargs):
        assert self._lock_fd is not None
        fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        os.close(self._lock_fd)
        self._lock_fd = None

    def _is_user_file(self, path):
        """Used as predicate when measuring user storage directories."""
        assert path.startswith(self._user_path + os.sep)
        path = path[len(self._user_path) + len(os.sep) :]
        # User files are under:
        # YYYY/MM/DD/NONCE/HASH (5 levels of nesting).
        # So a real user file has at least 6 components, which means it
        # must have at least 5 slashes.
        return path.count(os.sep) >= 5

    def copy(self, __id__, intake_path):
        """
        Copy a directory to user storage.
        Ensure that the user storage has room for the given number of files totaling the given number of bytes.
        If this is feasible by deleting previous user files, it will do so.
        Must be done while holding the lock.

        :param __id__: Chat or action ID.
        :param intake_path: Path to a directory that should be copied to the user storage.
        :raises OutOfStorageException: If there is not enough available file or bytes quota.
        :return: A list of `File`s from each file copied from `intake_path`.
        """
        assert (
            self._lock_fd is not None
        ), "Cannot perform this operation without holding the lock"
        want_num_files, want_num_bytes = self.measure_directory(intake_path)
        if want_num_files == 0:
            return ()  # Nothing to copy.
        if self._max_files_per_user <= want_num_files:
            raise self.OutOfStorageException(
                f"Cannot allocate storage for {want_num_files} files; maximum is {self._max_files_per_user} files per user"
            )
        if self._max_bytes_per_user <= want_num_bytes:
            raise self.OutOfStorageException(
                f"Cannot allocate storage for {want_num_bytes} bytes; maximum is {self._max_bytes_per_user} bytes per user"
            )
        disk_usage_free = shutil.disk_usage(self._user_path).free
        if (
            disk_usage_free
            <= want_num_bytes + self.MUST_KEEP_FREE_MARGIN_MEGABYTES * 1024 * 1024
        ):
            raise self.OutOfStorageException(
                f"Not enough free disk space for {want_num_bytes} bytes; current free space is {disk_usage_free} bytes and must keep at least {self.MUST_KEEP_FREE_MARGIN_MEGABYTES} megabytes free"
            )
        user_root_num_files, user_root_num_bytes = self.measure_directory(
            self._user_path,
            predicate=self._is_user_file,
        )
        user_root_remaining_files = self._max_files_per_user - user_root_num_files
        user_root_remaining_bytes = self._max_bytes_per_user - user_root_num_bytes
        while (
            user_root_remaining_files < want_num_files
            or user_root_remaining_bytes < want_num_bytes
        ):
            oldest_directory = None
            try:
                oldest_yyyy = next(
                    iter(
                        sorted(
                            f
                            for f in os.listdir(self._user_path)
                            if len(f) >= 4 and f.isdigit()
                        )
                    )
                )
                oldest_mm = next(
                    iter(
                        sorted(
                            f
                            for f in os.listdir(
                                os.path.join(self._user_path, oldest_yyyy)
                            )
                            if len(f) == 2 and f.isdigit()
                        )
                    )
                )
                oldest_dd = next(
                    iter(
                        sorted(
                            f
                            for f in os.listdir(
                                os.path.join(self._user_path, oldest_yyyy, oldest_mm)
                            )
                            if len(f) == 2 and f.isdigit()
                        )
                    )
                )
                oldest_nonce = next(
                    iter(
                        sorted(
                            f
                            for f in os.listdir(
                                os.path.join(
                                    self._user_path,
                                    oldest_yyyy,
                                    oldest_mm,
                                    oldest_dd,
                                )
                            )
                            if len(f) == self.NUM_NONCE_ZEROS and f.isdigit()
                        )
                    )
                )
                oldest_directory = os.path.join(
                    self._user_path, oldest_yyyy, oldest_mm, oldest_dd, oldest_nonce
                )
            except StopIteration:
                raise self.OutOfStorageException(
                    f"Cannot find directory to clear in order to make enough room for new user storage ({want_num_files} files, {want_num_bytes} bytes)"
                )
            assert oldest_directory is not None
            if not shutil.rmtree.avoids_symlink_attacks:
                raise self.EnvironmentNeedsSetupException(
                    "Only supported on platforms with symlink-attack-resistant rmtree implementations"
                )
            shutil.rmtree(oldest_directory)
            for parent_directory in (
                os.path.join(self._user_path, oldest_yyyy, oldest_mm, oldest_dd),
                os.path.join(self._user_path, oldest_yyyy, oldest_mm),
                os.path.join(self._user_path, oldest_yyyy),
            ):
                if len(os.listdir(parent_directory)) == 0:
                    os.rmdir(parent_directory)
            user_root_num_files, user_root_num_bytes = self.measure_directory(
                self._user_path,
                predicate=self._is_user_file,
            )
            user_root_remaining_files = self._max_files_per_user - user_root_num_files
            user_root_remaining_bytes = self._max_bytes_per_user - user_root_num_bytes

        # We now have enough. Find new directory name.
        path_with_counter = None
        max_nonce = 10**self.NUM_NONCE_ZEROS - 1
        for nonce in range(1, min(self._max_files_per_user or max_nonce, max_nonce)):
            path_with_counter = os.path.join(
                self._user_path, self._date, str(nonce).zfill(self.NUM_NONCE_ZEROS)
            )
            try:
                os.makedirs(path_with_counter, mode=0o755, exist_ok=False)
            except FileExistsError:
                pass
            else:
                break
        if path_with_counter is None:
            raise self.OutOfStorageException("No free storage directory available!")
        id_str = str(__id__) if __id__ is not None else self._date
        id_hash = hashlib.sha512()
        id_hash.update(self._user.encode("utf-8"))
        id_hash.update(b"||||")
        id_hash.update(self._date.encode("utf-8"))
        id_hash.update(b"||||")
        id_hash.update(path_with_counter.encode("utf-8"))
        id_hash.update(b"||||")
        id_hash.update(str(uuid.uuid4()).encode("utf-8"))
        id_hash.update(b"||||")
        id_hash.update(id_str.encode("utf-8"))
        id_hash_component = (
            base64.b32encode(id_hash.digest()).decode("ascii").lower()[:12]
        )
        final_path = os.path.normpath(
            os.path.abspath(os.path.join(path_with_counter, id_hash_component))
        )

        # Now do the copy.
        # This doesn't use `shutil.copytree` because we explicitly avoid copying anything but regular files.
        user_files = []
        for dirpath, subdirs, subfiles in os.walk(
            intake_path, onerror=None, followlinks=False
        ):
            dirpath = os.path.normpath(os.path.abspath(dirpath))
            relative_dirpath = None
            if dirpath == intake_path:
                relative_dirpath = "."
            elif dirpath.startswith(intake_path + os.sep):
                relative_dirpath = dirpath[len(intake_path) + len(os.sep) :]
            else:
                assert False, f"Bad traversal: expected all paths to starts with {intake_path} but got path that does not: {dirpath}"
            assert relative_dirpath is not None
            assert not os.path.isabs(relative_dirpath)
            copy_dirpath = os.path.join(final_path, relative_dirpath)
            os.makedirs(copy_dirpath, mode=0o755, exist_ok=True)
            for subfile in subfiles:
                subfile_path = os.path.join(dirpath, subfile)
                subfile_relative_path = os.path.normpath(
                    os.path.join(relative_dirpath, subfile)
                )
                assert not os.path.isabs(subfile_relative_path)
                subfile_stat = os.stat(subfile_path, follow_symlinks=False)
                if not stat.S_ISREG(subfile_stat.st_mode):
                    continue  # Ignore non-regular files.
                subfile_copy = os.path.join(copy_dirpath, subfile)
                assert subfile_copy.startswith(self._storage_root_path + os.sep)
                subfile_url = f"{self._storage_root_url}/" + urllib.parse.quote(
                    subfile_copy[len(self._storage_root_path) + len(os.sep) :],
                    safe=os.sep,
                )
                shutil.move(subfile_path, subfile_copy, copy_function=shutil.copy)
                user_files.append(
                    self.File(
                        file_path=subfile_copy,
                        file_relative_path=subfile_relative_path,
                        file_url=subfile_url,
                        file_size=subfile_stat.st_size,
                    )
                )

        # We are done.
        return user_files


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


def _do_self_tests(debug, filter=""):
    user_storage_path = None

    def _want_generated_files(want_generated_files):
        def _verify(got_generated_files):
            try:
                for name in want_generated_files.keys():
                    if name not in got_generated_files:
                        raise ValueError(f"File {name} is missing")
                for name in got_generated_files.keys():
                    if name not in want_generated_files:
                        raise ValueError(f"Unexpected generated file: {name}")
                for name, predicates in want_generated_files.items():
                    if type(predicates) not in (type(()), type([])):
                        predicates = (predicates,)
                    for i, predicate in enumerate(predicates):
                        try:
                            result = predicate(got_generated_files[name])
                            if result is not None:
                                raise ValueError(result)
                        except ValueError as e:
                            raise e.__class__(
                                f"File {name} predicate #{i}: {e} (got: {got_generated_files[name]})"
                            )
            except ValueError as e:
                return e
            else:
                return None

        return _verify

    def _markdown_contains(substring):
        return lambda md: (
            f"substring '{substring}' not found" if substring not in md else None
        )

    def _markdown_does_not_contain(substring):
        return lambda md: (
            f"substring '{substring}' unexpectedly found" if substring in md else None
        )

    def _want_user_storage_num_files(num_files_predicate):
        if type(num_files_predicate) is type(42):
            want_num_files = num_files_predicate

            def num_files_predicate_fn(n):
                return n == want_num_files

            num_files_predicate = num_files_predicate_fn

        def _verify():
            total_files = 0
            for _, _, subfiles in os.walk(user_storage_path):
                total_files += len(list(f for f in subfiles if f != ".lock"))
            if not num_files_predicate(total_files):
                raise ValueError(f"User storage unexpectedly has {total_files} files")

        return _verify

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
            "post": _want_user_storage_num_files(0),
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
            "name": "simple_file_creation",
            "language": "bash",
            "code": ("echo 'Hello world!' > today.txt",),
            "status": "OK",
            "generated_files": {
                "today.txt": (
                    _markdown_contains("today.txt"),
                    _markdown_contains("Hello world!\n"),
                )
            },
            "post": _want_user_storage_num_files(1),
        },
        {
            "name": "generated_file_rendering",
            "language": "bash",
            "code": (
                "mkdir -p foo/bar",
                "dmesg > foo/bar/dmesg.txt",
                "touch empty.txt",
                "(echo '# Example markdown file'; echo 'This is markdown!') > markdown.md",
                "echo 'This file cannot `''`''` be inlined' > no_inline.txt",
                "echo 'Might be an image' > picture.png",
                "echo 'Might be music' > song.flac",
                "echo 'Might be a video' > movie.mkv",
                "echo 'Might be random data' > random_data",
                "echo 'Might be random data' > random_data.bin",
            ),
            "valves": {
                "WEB_ACCESSIBLE_DIRECTORY_URL": "http://myhost/URL/ROOT",
            },
            "status": "OK",
            "generated_files": {
                "foo/bar/dmesg.txt": (
                    _markdown_contains("\U0001f4c4"),
                    _markdown_contains("[foo/bar/dmesg.txt]"),
                    _markdown_contains("(http://myhost/URL/ROOT/"),
                    _markdown_contains("/foo/bar/dmesg.txt)"),
                    _markdown_contains("gVisor"),
                    _markdown_contains("```"),
                ),
                "empty.txt": (
                    _markdown_contains("\u2049"),
                    _markdown_does_not_contain("\U0001f4c4"),
                    _markdown_contains("`empty.txt`"),
                    _markdown_contains("(empty)"),
                    _markdown_does_not_contain("[empty.txt]"),
                    _markdown_does_not_contain("(http://myhost/URL/ROOT"),
                ),
                "markdown.md": (
                    _markdown_contains("\U0001f4c3"),
                    _markdown_does_not_contain("\U0001f4c4"),
                    _markdown_contains(
                        "\n> # Example markdown file\n> This is markdown!"
                    ),
                    _markdown_does_not_contain("```"),
                ),
                "no_inline.txt": (
                    _markdown_contains("\U0001f4c4"),
                    _markdown_does_not_contain("This file cannot"),
                    _markdown_does_not_contain("```"),
                ),
                "picture.png": (
                    _markdown_contains("\U0001f5bc"),
                    _markdown_does_not_contain("Might be"),
                ),
                "song.flac": (
                    _markdown_contains("\U0001f3b5"),
                    _markdown_does_not_contain("Might be"),
                ),
                "movie.mkv": (
                    _markdown_contains("\U0001f3ac"),
                    _markdown_does_not_contain("Might be"),
                ),
                "random_data": (
                    _markdown_contains("\U0001f4be"),
                    _markdown_does_not_contain("Might be"),
                ),
                "random_data.bin": (
                    _markdown_contains("\U0001f4be"),
                    _markdown_does_not_contain("Might be"),
                ),
            },
            "post": _want_user_storage_num_files(10),
        },
        {
            "name": "generated_text_files_too_large_to_render",
            "language": "bash",
            "code": (
                f"yes boop | head -{UserStorage.File.MAX_INLINE_TEXT_LINES-1} > ok_lines.md",
                f"yes boop | head -{UserStorage.File.MAX_INLINE_TEXT_LINES-1} > ok_lines.txt",
                f"yes boop | head -{UserStorage.File.MAX_INLINE_TEXT_LINES+1} > too_many_lines.md",
                f"yes boop | head -{UserStorage.File.MAX_INLINE_TEXT_LINES+1} > too_many_lines.txt",
                f"yes boop | tr '\\n' ' ' | head -c{UserStorage.File.MAX_INLINE_TEXT_BYTES-1} > ok_bytes.txt",
                f"yes boop | tr '\\n' ' ' | head -c{UserStorage.File.MAX_INLINE_TEXT_BYTES+1} > too_many_bytes.txt",
            ),
            "status": "OK",
            "generated_files": {
                "ok_lines.md": _markdown_contains("boop"),
                "ok_lines.txt": _markdown_contains("boop"),
                "too_many_lines.md": _markdown_does_not_contain("boop"),
                "too_many_lines.txt": _markdown_does_not_contain("boop"),
                "ok_bytes.txt": _markdown_contains("boop"),
                "too_many_bytes.txt": _markdown_does_not_contain("boop"),
            },
            "post": _want_user_storage_num_files(16),
        },
        {
            "name": "too_large_file_for_user_quota",
            "language": "bash",
            "code": (f"head -c{64 * 1024 * 1024} /dev/urandom > random_data.bin",),
            "valves": {
                "MAX_MEGABYTES_PER_USER": 32,
                "MAX_RAM_MEGABYTES": 2048,
            },
            "status": "STORAGE_ERROR",
            "post": _want_user_storage_num_files(16),
        },
        {
            "name": "too_many_files_generated_in_single_execution",
            "language": "bash",
            "code": ("for i in $(seq 1 128); do touch file$i.txt; done",),
            "valves": {
                "MAX_FILES_PER_EXECUTION": 64,
            },
            "status": "STORAGE_ERROR",
            "post": _want_user_storage_num_files(16),
        },
        {
            "name": "too_many_files_for_user_quota",
            "language": "bash",
            "code": ("for i in $(seq 1 128); do touch file$i.txt; done",),
            "valves": {
                "MAX_FILES_PER_EXECUTION": 256,
                "MAX_FILES_PER_USER": 64,
            },
            "status": "STORAGE_ERROR",
            "post": _want_user_storage_num_files(16),
        },
        {
            "name": "clear_out_existing_user_storage",
            "language": "bash",
            "code": ("for i in $(seq 1 128); do touch file$i.txt; done",),
            "valves": {
                "MAX_FILES_PER_EXECUTION": 256,
                # Covers enough quota for the last test's files to not be
                # deleted (6 of them), but all previous tests' files will.
                # We add +2 which covers 2 of the previous-previous tests'
                # files, but since files from one execution are either all
                # deleted or not, this should not make a difference, so the
                # extra +2 should not add to the expected number of files.
                "MAX_FILES_PER_USER": 128 + 6 + 2,
            },
            "status": "OK",
            "generated_files": {f"file{i}.txt": () for i in range(1, 128 + 1)},
            # Verify that only this test + the last test's files are here:
            "post": _want_user_storage_num_files(128 + 6),
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
    ran_at_least_one = False

    with tempfile.TemporaryDirectory(prefix="sandbox_self_test") as tmp_dir:
        user_storage_path = os.path.join(tmp_dir, "user_storage")
        os.makedirs(user_storage_path, mode=0o755)
        valve_name_prefix = (
            _Action.Valves()._VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX
        )
        ran_at_least_one = False
        for self_test in _self_tests:
            name = self_test["name"]
            if filter and name != filter:
                continue
            ran_at_least_one = True
            language = self_test["language"]
            code = "\n".join(self_test["code"]) + "\n"
            want_status = self_test["status"]
            valves = self_test.get("valves", {})
            want_generated_files = self_test.get("generated_files", {})
            if type(want_generated_files) is type({}):
                want_generated_files = _want_generated_files(want_generated_files)
            post_tests = self_test.get("post", ())
            if type(post_tests) not in (type(()), type([])):
                post_tests = (post_tests,)
            test_env = os.environ.copy()
            test_env[f"{valve_name_prefix}WEB_ACCESSIBLE_DIRECTORY_PATH"] = (
                user_storage_path
            )
            for valve_name, valve_value in valves.items():
                test_env[f"{valve_name_prefix}{valve_name}"] = str(valve_value)
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
                    f"\u274c Self-test {name} failed: process failed: {e}",
                    file=sys.stderr,
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
                        f"\u274c Self-test {name} failed: JSON decoding failed: {e}; got: {result.stdout}",
                        file=sys.stderr,
                    )
                else:
                    if debug:
                        _print_output(result)
                    got_status = result_data["status"]
                    got_generated_files = result_data.get("generated_files", {})
                    if got_status != want_status:
                        success = False
                        print(
                            f"\u274c Self-test {name} failed: status was {got_status}, expected {want_status}",
                            file=sys.stderr,
                        )
                    elif want_generated_files(got_generated_files) is not None:
                        success = False
                        generated_files_error = want_generated_files(
                            got_generated_files
                        )
                        print(
                            f"\u274c Self-test {name} failed: generated files are incorrect: {generated_files_error}",
                            file=sys.stderr,
                        )
                    else:
                        post_test_failure = None
                        for post_test in post_tests:
                            try:
                                post_test()
                            except Exception as e:
                                post_test_failure = e
                                break
                        if post_test_failure is not None:
                            success = False
                            print(
                                f"\u274c Self-test {name} failed: post-test verification failed: {post_test_failure}",
                                file=sys.stderr,
                            )
                        else:
                            print(f"\u2714 Self-test {name} passed.", file=sys.stderr)
    if not ran_at_least_one:
        print("\u2620 No tests were ran.", file=sys.stderr)
        sys.exit(1)
    if success:
        print("\u2705 All function self-tests passed, good go to!", file=sys.stderr)
        sys.exit(0)
    else:
        print("\u2620 One or more function self-tests failed.", file=sys.stderr)
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
        "--self_test_filter",
        type=str,
        default="",
        help="If set, run only this self-test.",
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
            _Action.Valves()._VALVE_OVERRIDE_ENVIRONMENT_VARIABLE_NAME_PREFIX + "DEBUG"
        ] = "true"

    if args.self_test:
        _do_self_tests(debug=args.debug, filter=args.self_test_filter)

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

        action = Action()
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "content": f"```{args.language}\n{code}\n```\n",
                },
            ],
        }
        output_str = await action.action(body=body, __event_emitter__=_dummy_emitter)
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
