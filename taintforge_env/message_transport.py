"""Bounded UDP messages and length-prefixed DNS/TCP with explicit cleanup."""
from __future__ import annotations

import asyncio
import socket
import struct
from typing import Awaitable, Callable

from .network_events import ObservedReply
from .network_runtime import current_runtime, NetworkRuntimeError
from .network_runtime_transport import start_server as runtime_start_server, received_datagram, sending, release


Handler = Callable[[bytes, tuple], Awaitable[bytes | ObservedReply | None]]


class MessageServer(asyncio.DatagramProtocol):
    def __init__(self, handler: Handler, *, max_pending: int = 32, timeout: float = 10):
        self.handler = handler
        self.max_pending = max_pending
        self.timeout = timeout
        self.tasks: set[asyncio.Task] = set()
        self.writers: set[asyncio.StreamWriter] = set()
        self.transport = None
        self.udp_socket = None
        self.server = None
        self.closed = False
        self.dropped = 0
        self.listener_lease = None

    async def start(self, host: str, port: int, transport: str) -> MessageServer:
        if transport == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setblocking(False)
                sock.bind((host, port))
                runtime = current_runtime()
                if runtime is not None:
                    self.listener_lease = runtime.call("listen")
                self.udp_socket = sock
                asyncio.get_running_loop().add_reader(sock.fileno(), self._readable)
            except BaseException:
                sock.close()
                raise
        elif transport == "tcp":
            self.server = await runtime_start_server(self._tcp, host, port, family=socket.AF_INET)
        else:
            raise ValueError("unsupported message transport")
        return self

    @property
    def sockets(self):
        return self.server.sockets if self.server else (self.udp_socket,)

    def _readable(self):
        for _ in range(128):
            try:
                data, addr = self.udp_socket.recvfrom(65536)
            except BlockingIOError:
                return
            except OSError:
                self.dropped += 1
                return
            self.datagram_received(data, addr)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if self.closed or len(self.tasks) >= self.max_pending:
            self.dropped += 1
            return
        runtime = current_runtime()
        lease = None
        try:
            if runtime is not None:
                lease = runtime.call("slot", kind="message")
                if lease is None:
                    self.dropped += 1
                    return
                received_datagram(data)
        except NetworkRuntimeError:
            release(runtime, lease)
            self.dropped += 1
            return
        task = asyncio.create_task(self._udp(data, addr))
        self.tasks.add(task)
        def finished(task):
            self.tasks.discard(task)
            release(runtime, lease)
        task.add_done_callback(finished)

    async def _udp(self, data, addr):
        reply = None
        try:
            async with asyncio.timeout(self.timeout):
                response = await self.handler(data, addr)
                reply = response if isinstance(response, ObservedReply) else None
                payload = reply.payload if reply is not None else response
                if payload is not None:
                    if self.closed:
                        raise OSError("message server closed before sending response")
                    if len(payload) > 65507:
                        raise ValueError("response exceeds IPv4 UDP datagram size")
                    sending(payload)
                    await asyncio.get_running_loop().sock_sendto(self.udp_socket, payload, addr)
        except asyncio.CancelledError:
            if reply is not None:
                reply.delivery(sent=False, error="CancelledError")
            raise
        except (OSError, ValueError, TimeoutError, NetworkRuntimeError) as exc:
            self.dropped += 1
            if reply is not None:
                reply.delivery(sent=False, error=f"{type(exc).__name__}: {exc}")
        else:
            if reply is not None:
                reply.delivery(sent=True)

    async def _tcp(self, reader, writer):
        task = asyncio.current_task()
        if self.closed or len(self.tasks) >= self.max_pending:
            writer.close()
            await writer.wait_closed()
            self.dropped += 1
            return
        self.tasks.add(task)
        self.writers.add(writer)
        try:
            for _ in range(128):
                reply = None
                try:
                    async with asyncio.timeout(self.timeout):
                        size = struct.unpack("!H", await reader.readexactly(2))[0]
                        if size < 12:
                            raise ValueError("invalid DNS/TCP frame size")
                        runtime = current_runtime()
                        if runtime is not None:
                            runtime.call("message")
                        data = await reader.readexactly(size)
                        response = await self.handler(data, writer.get_extra_info("peername"))
                        reply = response if isinstance(response, ObservedReply) else None
                        payload = reply.payload if reply is not None else response
                        if payload is None:
                            return
                        writer.write(struct.pack("!H", len(payload)) + payload)
                        await writer.drain()
                except BaseException as exc:
                    if reply is not None:
                        reply.delivery(sent=False, error=f"{type(exc).__name__}: {exc}")
                    raise
                if reply is not None:
                    reply.delivery(sent=True)
        except (asyncio.IncompleteReadError, OSError, ValueError, TimeoutError):
            pass
        finally:
            self.tasks.discard(task)
            self.writers.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    def close(self):
        self.closed = True
        if self.listener_lease is not None:
            try:
                current_runtime().call("unlisten", key=self.listener_lease)
            except (NetworkRuntimeError, AttributeError):
                pass
            self.listener_lease = None
        if self.udp_socket and self.udp_socket.fileno() >= 0:
            asyncio.get_running_loop().remove_reader(self.udp_socket.fileno())
            self.udp_socket.close()
        if self.transport:
            self.transport.close()
        if self.server:
            self.server.close()
        for writer in tuple(self.writers):
            writer.close()
        for task in tuple(self.tasks):
            task.cancel()

    async def wait_closed(self):
        if self.server:
            await self.server.wait_closed()
        if self.tasks:
            runtime = current_runtime()
            timeout = runtime.limits.shutdown_timeout_ms / 1000 if runtime else 5
            _, pending = await asyncio.wait(tuple(self.tasks), timeout=timeout)
            if pending:
                raise NetworkRuntimeError("message handlers did not stop")

    async def serve_forever(self):
        await asyncio.Future()
