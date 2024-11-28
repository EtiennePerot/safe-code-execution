# :: This file is *NOT* directly installable into Open WebUI.
# :: It is used as part of the development workflow.
# :: If you are looking for the function to install in Open WebUI, see:
# :: https://github.com/EtiennePerot/safe-code-execution/blob/master/README.md

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


# :: Note: All lines with '# ::' in them in this file will be removed in the
# :: released version of this tool.
# fmt: off
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))  # ::
from openwebui.event_emitter import EventEmitter, CodeExecutionTracker  # INLINE_IMPORT # noqa: E402
from safecode.sandbox import Sandbox  # INLINE_IMPORT # noqa: E402
from safecode.user_storage import UserStorage  # INLINE_IMPORT # noqa: E402
from safecode.update_check import UpdateCheck  # INLINE_IMPORT # noqa: E402
UpdateCheck.disable()  # ::
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
