"""Budgeted transports used by every network service entry point."""
from __future__ import annotations

import asyncio

from .network_runtime import NetworkRuntimeError, current_runtime


def release(runtime, lease, used=0):
    if lease is not None:
        try:
            runtime.call("release", lease=lease, used=used)
        except NetworkRuntimeError:
            pass


def received_datagram(data, runtime=None):
    runtime = runtime if runtime is not None else current_runtime()
    if runtime is not None and data:
        allocation = runtime.call("receive", size=len(data), exact=True)
        runtime.call("release", lease=allocation["lease"], used=len(data))


def sending(data):
    runtime = current_runtime()
    if runtime is not None:
        runtime.call("send", size=len(data))


class RuntimeReader:
    def __init__(self, reader, runtime):
        self.reader, self.runtime = reader, runtime

    def __getattr__(self, name):
        return getattr(self.reader, name)

    async def _read(self, size, exact):
        if size == 0 or self.reader.at_eof():
            if exact and size > 0:
                raise asyncio.IncompleteReadError(b"", size)
            return b""
        size = 65536 if size < 0 else min(size, 1024 * 1024)
        try:
            async with asyncio.timeout(self.runtime.limits.idle_timeout_ms / 1000):
                data = await (self.reader.readexactly(size) if exact else self.reader.read(size))
        except asyncio.IncompleteReadError as exc:
            received_datagram(exc.partial, self.runtime)
            raise
        # Reserve before exposing bytes to the application or persisting them.
        # Idle sockets must not reserve all receive capacity while holding no data.
        received_datagram(data, self.runtime)
        return data

    async def read(self, size=-1):
        # Preserve read-to-EOF behavior while bounding each reservation.
        if size >= 0:
            return await self._read(size, False)
        chunks = []
        while True:
            data = await self._read(65536, False)
            if not data:
                return b"".join(chunks)
            chunks.append(data)

    async def readexactly(self, size):
        if size > 1024 * 1024:
            raise NetworkRuntimeError("network frame exceeds its runtime bound")
        return await self._read(size, True)


class RuntimeWriter:
    def __init__(self, writer, runtime):
        self.writer, self.runtime = writer, runtime

    def __getattr__(self, name):
        return getattr(self.writer, name)

    def write(self, data):
        self.runtime.call("send", size=len(data))
        return self.writer.write(data)

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    async def drain(self):
        async with asyncio.timeout(self.runtime.limits.idle_timeout_ms / 1000):
            return await self.writer.drain()

    async def wait_closed(self):
        try:
            async with asyncio.timeout(min(1, self.runtime.limits.shutdown_timeout_ms / 1000)):
                await self.writer.wait_closed()
        except TimeoutError:
            self.writer.transport.abort()


class RuntimeListener:
    def __init__(self, runtime):
        self.runtime, self.server = runtime, None
        self.tasks, self.writers = set(), set()
        self.closed = False
        self.listener_lease = None

    @property
    def sockets(self):
        return self.server.sockets

    def is_serving(self):
        return self.server.is_serving()

    async def serve_forever(self):
        await self.server.serve_forever()

    def close(self):
        if self.listener_lease is not None:
            try:
                self.runtime.call("unlisten", key=self.listener_lease)
            except NetworkRuntimeError:
                pass
            self.listener_lease = None
        self.closed = True
        self.server.close()
        for writer in tuple(self.writers):
            writer.close()
        for task in tuple(self.tasks):
            task.cancel()

    async def wait_closed(self):
        await self.server.wait_closed()
        await asyncio.sleep(0)
        if self.tasks:
            _, pending = await asyncio.wait(tuple(self.tasks), timeout=self.runtime.limits.shutdown_timeout_ms / 1000)
            if pending:
                for writer in tuple(self.writers):
                    writer.transport.abort()
                self.runtime.fail("network_task_cleanup_failed")
                raise NetworkRuntimeError("network tasks did not stop within their deadline")


async def start_server(handler, *args, **kwargs):
    runtime = current_runtime()
    if runtime is None:
        return await asyncio.start_server(handler, *args, **kwargs)
    listener = RuntimeListener(runtime)

    async def dispatch(reader, writer, lease):
        task = asyncio.current_task()
        try:
            async with asyncio.timeout(runtime.limits.connection_timeout_ms / 1000):
                await handler(RuntimeReader(reader, runtime), RuntimeWriter(writer, runtime))
        except NetworkRuntimeError as exc:
            runtime.fail(str(exc))
        except (ConnectionError, OSError, TimeoutError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception:
            runtime.fail("network_service_handler_failed")
            raise
        finally:
            writer.close()
            try:
                async with asyncio.timeout(1):
                    await writer.wait_closed()
            except (TimeoutError, OSError):
                writer.transport.abort()
            finally:
                release(runtime, lease)
                listener.tasks.discard(task)
                listener.writers.discard(writer)

    def accept(reader, writer):
        if listener.closed:
            writer.transport.abort()
            return
        try:
            lease = runtime.call("slot", kind="tcp")
        except NetworkRuntimeError:
            writer.transport.abort()
            return
        if lease is None:
            writer.transport.abort()
            return
        listener.writers.add(writer)
        task = asyncio.create_task(dispatch(reader, writer, lease))
        listener.tasks.add(task)

    listener.server = await asyncio.start_server(accept, *args, **kwargs)
    try:
        listener.listener_lease = runtime.call("listen")
    except BaseException:
        listener.server.close()
        await listener.server.wait_closed()
        raise
    return listener


async def open_connection(*args, **kwargs):
    reader, writer = await asyncio.open_connection(*args, **kwargs)
    runtime = current_runtime()
    if runtime is None:
        return reader, writer
    return RuntimeReader(reader, runtime), RuntimeWriter(writer, runtime)


def dispatch_datagram(handler, data, peer):
    runtime = current_runtime()
    if runtime is None:
        return handler(data, peer)
    lease = None
    try:
        lease = runtime.call("slot", kind="message")
        if lease is not None:
            received_datagram(data)
            return handler(data, peer)
    except NetworkRuntimeError:
        return None
    finally:
        release(runtime, lease)
