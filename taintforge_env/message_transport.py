"""Bounded UDP messages and length-prefixed DNS/TCP with explicit cleanup."""
from __future__ import annotations

import asyncio
import socket
import struct
from typing import Awaitable, Callable


Handler = Callable[[bytes, tuple], Awaitable[bytes | None]]


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

    async def start(self, host: str, port: int, transport: str) -> MessageServer:
        if transport == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setblocking(False)
                sock.bind((host, port))
                self.udp_socket = sock
                asyncio.get_running_loop().add_reader(sock.fileno(), self._readable)
            except BaseException:
                sock.close()
                raise
        elif transport == "tcp":
            self.server = await asyncio.start_server(self._tcp, host, port, family=socket.AF_INET)
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
        task = asyncio.create_task(self._udp(data, addr))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _udp(self, data, addr):
        try:
            async with asyncio.timeout(self.timeout):
                response = await self.handler(data, addr)
            if response is not None and not self.closed:
                if len(response) > 65507:
                    raise ValueError("response exceeds IPv4 UDP datagram size")
                await asyncio.get_running_loop().sock_sendto(self.udp_socket, response, addr)
        except (OSError, ValueError, TimeoutError):
            self.dropped += 1

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
                async with asyncio.timeout(self.timeout):
                    size = struct.unpack("!H", await reader.readexactly(2))[0]
                    if size < 12:
                        raise ValueError("invalid DNS/TCP frame size")
                    data = await reader.readexactly(size)
                    response = await self.handler(data, writer.get_extra_info("peername"))
                    if response is None:
                        return
                    writer.write(struct.pack("!H", len(response)) + response)
                    await writer.drain()
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
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)

    async def serve_forever(self):
        await asyncio.Future()
