import asyncio
import inspect
import sys
import typing
import uuid


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
