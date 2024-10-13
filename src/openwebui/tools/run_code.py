# :: This file is *NOT* directly installable into Open WebUI.
# :: It is used as part of the development workflow.
# :: If you are looking for the tool to install in Open WebUI, see:
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


# :: Note: All lines with '# ::' in them in this file will be removed in the
# :: released version of this tool.
# fmt: off
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))  # ::
from openwebui.event_emitter import EventEmitter, CodeExecutionTracker  # INLINE_IMPORT # noqa: E402
from safecode.sandbox import Sandbox  # INLINE_IMPORT # noqa: E402
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
