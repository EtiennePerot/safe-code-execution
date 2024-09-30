import asyncio
import inspect
import typing
import sys


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

    def set_status_prefix(self, status_prefix):
        self._status_prefix = status_prefix

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
        if self._status_prefix is not None:
            description = f"{self._status_prefix}{description}"
        await self._emit(
            "status",
            {
                "status": status,
                "description": description,
                "done": done,
            },
        )
        if not done and len(description) <= 1024:
            # Emit it again; Open WebUI does not seem to flush this reliably.
            # Only do it for relatively small statuses; when debug mode is enabled,
            # this can take up a lot of space.
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

    async def message(self, content):
        await self._emit(
            "message",
            {
                "content": content,
            },
        )

    async def citation(self, document, metadata, source):
        await self._emit(
            "citation",
            {
                "document": document,
                "metadata": metadata,
                "source": source,
            },
        )

    async def code_execution_result(self, output):
        await self._emit(
            "code_execution_result",
            {
                "output": output,
            },
        )