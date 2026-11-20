from __future__ import annotations

from .network_runtime import network_open, network_write, current_runtime, NetworkRuntimeError
from .network_runtime_transport import start_server as runtime_start_server, received_datagram, sending, release
import subprocess
import asyncio
import hashlib
import socket
import struct
from pathlib import Path

from .event_logger import append_jsonl_event
from .network_events import payload_fingerprints


SO_ORIGINAL_DST = 80
IP_RECVORIGDSTADDR = 20

PREVIEW_BYTES = 64
TCP_RESPONSE = b"OK\n"
HTTP_METHODS = {
    "GET",
    "POST",
    "HEAD",
    "PUT",
    "DELETE",
    "OPTIONS",
    "PATCH",
}


def parse_http_request(data: bytes) -> dict:
    try:
        text = data.decode("iso-8859-1", errors="replace")
    except Exception as e:
        return {
            "http_parse_ok": False,
            "http_parse_error": f"decode_failed:{e}",
        }

    if "\r\n" in text:
        lines = text.split("\r\n")
        header_separator = "\r\n\r\n"
    else:
        lines = text.split("\n")
        header_separator = "\n\n"

    if not lines:
        return {
            "http_parse_ok": False,
            "http_parse_error": "empty_request",
        }

    request_line = lines[0].strip()
    parts = request_line.split()

    if len(parts) < 3:
        return {
            "http_parse_ok": False,
            "http_parse_error": "bad_request_line",
            "http_request_line": request_line,
        }

    method, path, version = parts[0], parts[1], parts[2]

    if method.upper() not in HTTP_METHODS:
        return {
            "http_parse_ok": False,
            "http_parse_error": "unknown_method",
            "http_request_line": request_line,
        }

    headers: dict[str, str] = {}

    for line in lines[1:]:
        line = line.strip()

        if not line:
            break

        if ":" not in line:
            continue

        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    body = b""
    marker = header_separator.encode("iso-8859-1")

    if marker in data:
        body = data.split(marker, 1)[1]

    return {
        "http_parse_ok": True,
        "http_method": method.upper(),
        "http_path": path,
        "http_version": version,
        "http_host": headers.get("host"),
        "http_user_agent": headers.get("user-agent"),
        "http_content_type": headers.get("content-type"),
        "http_body_size": len(body),
        "http_body_hex_preview": body[:PREVIEW_BYTES].hex(),
        "http_request_line": request_line,
    }


def build_http_response() -> bytes:
    body = b"TaintForge-IoT fake HTTP service\n"

    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Connection: close\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )



def lookup_udp_original_destination_conntrack(
    peer_host: str | None,
    peer_port: int | None,
) -> tuple[str | None, int | None]:
    if not peer_host or peer_port is None:
        return None, None

    try:
        result = subprocess.run(
            ["conntrack", "-L", "-p", "udp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
            check=False,
        )
    except Exception:
        return None, None

    for line in result.stdout.splitlines():
        original = parse_conntrack_original_tuple(line)

        if original is None:
            continue

        src_ip, dst_ip, src_port, dst_port = original

        if src_ip == peer_host and src_port == peer_port:
            return dst_ip, dst_port

    return None, None


def parse_conntrack_original_tuple(
    line: str,
) -> tuple[str, str, int, int] | None:
    fields: dict[str, str] = {}

    for token in line.split():
        if "=" not in token:
            continue

        key, value = token.split("=", 1)

        # conntrack line has two tuples:
        # original: src=... dst=... sport=... dport=...
        # reply:    src=... dst=... sport=... dport=...
        #
        # We only want the first/original occurrence.
        if key in {"src", "dst", "sport", "dport"} and key not in fields:
            fields[key] = value

        if {"src", "dst", "sport", "dport"} <= fields.keys():
            break

    try:
        return (
            fields["src"],
            fields["dst"],
            int(fields["sport"]),
            int(fields["dport"]),
        )
    except (KeyError, ValueError):
        return None

def parse_sockaddr_in(raw: bytes) -> tuple[str | int | None, int | None]:
    if len(raw) < 8:
        return None, None

    port = struct.unpack("!H", raw[2:4])[0]
    ip = socket.inet_ntoa(raw[4:8])

    return ip, port


def safe_name(value: str | int | None) -> str:
    if value is None:
        return "unknown"

    return str(value).replace(".", "_").replace(":", "_").replace("/", "_")


def guess_udp_role(port: int | None) -> str:
    if port == 53:
        return "dns"

    if port == 123:
        return "ntp"

    return "udp"

DNS_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}


def parse_dns_query(packet: bytes) -> dict:
    if len(packet) < 12:
        return {
            "dns_parse_ok": False,
            "dns_parse_error": "packet_too_short",
        }

    try:
        transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH",
            packet[:12],
        )
    except struct.error as e:
        return {
            "dns_parse_ok": False,
            "dns_parse_error": f"header_unpack_failed:{e}",
        }

    if qdcount < 1:
        return {
            "dns_parse_ok": False,
            "dns_parse_error": "no_questions",
            "dns_transaction_id": transaction_id,
        }

    offset = 12
    labels: list[str] = []

    try:
        while True:
            if offset >= len(packet):
                return {
                    "dns_parse_ok": False,
                    "dns_parse_error": "qname_out_of_bounds",
                    "dns_transaction_id": transaction_id,
                }

            length = packet[offset]
            offset += 1

            if length == 0:
                break

            if length & 0xC0:
                return {
                    "dns_parse_ok": False,
                    "dns_parse_error": "compressed_qname_not_supported",
                    "dns_transaction_id": transaction_id,
                }

            if offset + length > len(packet):
                return {
                    "dns_parse_ok": False,
                    "dns_parse_error": "label_out_of_bounds",
                    "dns_transaction_id": transaction_id,
                }

            labels.append(
                packet[offset:offset + length].decode("ascii", errors="replace")
            )
            offset += length

        if offset + 4 > len(packet):
            return {
                "dns_parse_ok": False,
                "dns_parse_error": "question_tail_out_of_bounds",
                "dns_transaction_id": transaction_id,
            }

        qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])

        return {
            "dns_parse_ok": True,
            "dns_transaction_id": transaction_id,
            "dns_flags": flags,
            "dns_qdcount": qdcount,
            "dns_query": ".".join(labels),
            "dns_qtype": qtype,
            "dns_qtype_name": DNS_QTYPE_NAMES.get(qtype, str(qtype)),
            "dns_qclass": qclass,
            "dns_question_end_offset": offset + 4,
        }

    except Exception as e:
        return {
            "dns_parse_ok": False,
            "dns_parse_error": f"unexpected:{type(e).__name__}:{e}",
            "dns_transaction_id": transaction_id,
        }


def build_dns_empty_response(query_packet: bytes, info: dict) -> bytes | None:
    try:
        transaction_id = int(info["dns_transaction_id"])
        query_flags = int(info.get("dns_flags", 0))
        question_end = int(info["dns_question_end_offset"])
    except Exception:
        return None

    question = query_packet[12:question_end]

    # QR=1, RA=1, RD copied from query, RCODE=0, ANCOUNT=0.
    response_flags = 0x8000 | 0x0080 | (query_flags & 0x0100)

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        response_flags,
        1,
        0,
        0,
        0,
    )

    return header + question


def build_dns_a_response(
    query_packet: bytes,
    answer_ip: str = "10.10.0.1",
    ttl: int = 60,
) -> bytes | None:
    info = parse_dns_query(query_packet)

    if not info.get("dns_parse_ok"):
        return None

    qtype = int(info.get("dns_qtype", 0))
    qclass = int(info.get("dns_qclass", 0))

    # MVP: only answer IN A queries. For AAAA/TXT/etc return valid empty response.
    if qtype != 1 or qclass != 1:
        return build_dns_empty_response(query_packet, info)

    transaction_id = int(info["dns_transaction_id"])
    query_flags = int(info.get("dns_flags", 0))
    question_end = int(info["dns_question_end_offset"])

    question = query_packet[12:question_end]

    # QR=1, RA=1, RD copied from query, RCODE=0.
    response_flags = 0x8000 | 0x0080 | (query_flags & 0x0100)

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        response_flags,
        1,  # QDCOUNT
        1,  # ANCOUNT
        0,
        0,
    )

    answer_name = b"\xC0\x0C"
    answer_type = 1
    answer_class = 1
    answer_rdata = bytes(int(part) for part in answer_ip.split("."))

    answer = (
        answer_name
        + struct.pack("!HHIH", answer_type, answer_class, ttl, len(answer_rdata))
        + answer_rdata
    )

    return header + question + answer

def is_redirected_udp_destination(
    original_ip: str | None,
    original_port: int | None,
    bind_ip: str,
    bind_port: int,
) -> bool:
    if original_ip is None or original_port is None:
        return True

    if original_port != bind_port:
        return False

    return original_ip in {
        bind_ip,
        "127.0.0.1",
        "0.0.0.0",
    }


class TransparentTCPLogger:
    def __init__(
        self,
        bind_ip: str,
        bind_port: int,
        log_dir: str | Path,
    ):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.events_log_path = self.log_dir / "network_events.jsonl"
        self.connection_counter = 0

    async def start(self) -> asyncio.AbstractServer:
        server = await runtime_start_server(
            self.handle_client,
            host=self.bind_ip,
            port=self.bind_port,
        )

        print(
            f"[+] Transparent TCP catch-all logger listening on "
            f"{self.bind_ip}:{self.bind_port}"
        )

        return server

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.connection_counter += 1
        conn_id = self.connection_counter

        peer = writer.get_extra_info("peername")
        peer_host, peer_port = self.parse_peer(peer)

        sock = writer.get_extra_info("socket")
        original_ip, original_port = self.get_original_tcp_destination(sock)

        payload_file = (
            f"catchall_tcp_"
            f"{safe_name(original_ip)}_"
            f"{safe_name(original_port)}_"
            f"conn_{conn_id}.bin"
        )

        payload_path = self.log_dir / payload_file

        append_jsonl_event(
            self.events_log_path,
            {
                "event": "tcp_connection_open",
                "listener_type": "catch_all_transparent",
                "connection_id": conn_id,
                "peer_host": peer_host,
                "peer_port": peer_port,
                "bind_ip": self.bind_ip,
                "bind_port": self.bind_port,
                "original_remote_ip": original_ip,
                "original_remote_port": original_port,
                "payload_file": payload_file,
            },
        )

        try:
            with network_open(payload_path, "ab") as f:
                while True:
                    data = await reader.read(4096)

                    if not data:
                        append_jsonl_event(
                            self.events_log_path,
                            {
                                "event": "tcp_connection_close",
                                "listener_type": "catch_all_transparent",
                                "connection_id": conn_id,
                                "peer_host": peer_host,
                                "peer_port": peer_port,
                                "bind_ip": self.bind_ip,
                                "bind_port": self.bind_port,
                                "original_remote_ip": original_ip,
                                "original_remote_port": original_port,
                                "payload_file": payload_file,
                            },
                        )

                        break

                    f.write(data)
                    f.flush()

                    http_info = parse_http_request(data)

                    data_event = {
                        "event": "tcp_data",
                        "transport": "tcp",
                        "request_sha256": hashlib.sha256(data).hexdigest(),
                        "listener_type": "catch_all_transparent",
                        "connection_id": conn_id,
                        "peer_host": peer_host,
                        "peer_port": peer_port,
                        "bind_ip": self.bind_ip,
                        "bind_port": self.bind_port,
                        "original_remote_ip": original_ip,
                        "original_remote_port": original_port,
                        "payload_file": payload_file,
                        "bytes_received": len(data),
                        "payload_hex_preview": data[:PREVIEW_BYTES].hex(),
                    }

                    if http_info.get("http_parse_ok"):
                        data_event.update(http_info)

                    append_jsonl_event(self.events_log_path, data_event)

                    if http_info.get("http_parse_ok"):
                        response = build_http_response()
                        response_type = "http_200_ok"
                    else:
                        response = TCP_RESPONSE
                        response_type = "generic_ok"

                    writer.write(response)
                    await writer.drain()

                    append_jsonl_event(
                        self.events_log_path,
                        {
                            "event": "tcp_response",
                            "network_event_version": 1,
                            "transport": "tcp",
                            "request_sha256": hashlib.sha256(data).hexdigest(),
                            "response_sha256": hashlib.sha256(response).hexdigest(),
                            "response_prepared": True,
                            "response_sent": True,
                            "response_origin": "synthetic",
                            "listener_type": "catch_all_transparent",
                            "connection_id": conn_id,
                            "peer_host": peer_host,
                            "peer_port": peer_port,
                            "bind_ip": self.bind_ip,
                            "bind_port": self.bind_port,
                            "original_remote_ip": original_ip,
                            "original_remote_port": original_port,
                            "payload_file": payload_file,
                            "bytes_sent": len(response),
                            "response_type": response_type,
                            "response_hex_preview": response[:PREVIEW_BYTES].hex(),
                        },
                    )

        except ConnectionResetError:
            append_jsonl_event(
                self.events_log_path,
                {
                    "event": "tcp_connection_reset",
                    "listener_type": "catch_all_transparent",
                    "connection_id": conn_id,
                    "peer_host": peer_host,
                    "peer_port": peer_port,
                    "bind_ip": self.bind_ip,
                    "bind_port": self.bind_port,
                    "original_remote_ip": original_ip,
                    "original_remote_port": original_port,
                    "payload_file": payload_file,
                },
            )

        finally:
            writer.close()
            await writer.wait_closed()

    @staticmethod
    def get_original_tcp_destination(sock) -> tuple[str | None, int | None]:
        if sock is None:
            return None, None

        try:
            raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            ip, port = parse_sockaddr_in(raw)
            return str(ip), port
        except OSError:
            return None, None

    @staticmethod
    def parse_peer(peer) -> tuple[str | None, int | None]:
        if not peer:
            return None, None

        if isinstance(peer, tuple) and len(peer) >= 2:
            return str(peer[0]), int(peer[1])

        return str(peer), None


class TransparentUDPLogger:
    def __init__(
        self,
        bind_ip: str,
        bind_port: int,
        log_dir: str | Path,
    ):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.events_log_path = self.log_dir / "network_events.jsonl"
        self.datagram_counter = 0
        self.sock: socket.socket | None = None

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        sock.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
        sock.bind((self.bind_ip, self.bind_port))

        self.sock = sock

        loop = asyncio.get_running_loop()
        loop.add_reader(sock.fileno(), self.handle_readable)

        print(
            f"[+] Transparent UDP logger listening on "
            f"{self.bind_ip}:{self.bind_port}"
        )

    def handle_readable(self) -> None:
        if self.sock is None:
            return

        for _ in range(128):
            try:
                data, ancdata, _flags, peer = self.sock.recvmsg(
                    65535,
                    1024,
                )
            except BlockingIOError:
                break

            runtime = current_runtime()
            lease = None
            try:
                if runtime is not None:
                    lease = runtime.call("slot", kind="message")
                    if lease is None:
                        continue
                    received_datagram(data)
                self.handle_datagram(data, ancdata, peer)
            except NetworkRuntimeError:
                return
            finally:
                release(runtime, lease)

    def handle_datagram(self, data, ancdata, peer):
        self.datagram_counter += 1
        datagram_id = self.datagram_counter

        peer_host, peer_port = self.parse_peer(peer)

        original_ip, original_port = self.extract_udp_original_destination(ancdata)

        original_destination_source = "recvmsg"

        if is_redirected_udp_destination(
            original_ip=original_ip,
            original_port=original_port,
            bind_ip=self.bind_ip,
            bind_port=self.bind_port,
        ):
            ct_ip, ct_port = lookup_udp_original_destination_conntrack(peer_host=peer_host,peer_port=peer_port)

            if ct_ip is not None and ct_port is not None:
                original_ip = ct_ip
                original_port = ct_port
                original_destination_source = "conntrack"
            else:
                original_destination_source = "recvmsg_redirected"

        udp_role = guess_udp_role(original_port)

        payload_file = (
            f"{udp_role}_udp_"
            f"{safe_name(original_ip)}_"
            f"{safe_name(original_port)}_"
            f"dgram_{datagram_id}.bin"
        )

        payload_path = self.log_dir / payload_file
        network_write(payload_path, data)

        dns_info: dict = {}
        dns_response: bytes | None = None
        dns_answer_ip = "10.10.0.1"

        if udp_role == "dns":
            dns_info = parse_dns_query(data)

            if dns_info.get("dns_parse_ok"):
                dns_response = build_dns_a_response(
                    query_packet=data,
                    answer_ip=dns_answer_ip,
                )

                dns_info["dns_answer_ip"] = dns_answer_ip
                dns_info["dns_response_sent"] = False
            else:
                dns_info["dns_response_sent"] = False

        event = {
            "event": "udp_datagram",
            "network_event_version": 1,
            "transport": "udp",
            "request_sha256": hashlib.sha256(data).hexdigest(),
            "response_prepared": dns_response is not None,
            "response_origin": "synthetic" if dns_response is not None else None,
            "listener_type": "udp_transparent",
            "datagram_id": datagram_id,
            "udp_role": udp_role,
            "peer_host": peer_host,
            "peer_port": peer_port,
            "bind_ip": self.bind_ip,
            "bind_port": self.bind_port,
            "original_remote_ip": original_ip,
            "original_remote_port": original_port,
            "original_destination_source": original_destination_source,
            "payload_file": payload_file,
            "bytes_received": len(data),
            "payload_hex_preview": data[:PREVIEW_BYTES].hex(),
        }

        event.update(dns_info)
        event.update(payload_fingerprints(data, dns_response, dns=udp_role == "dns"))

        if dns_response is not None and self.sock is not None:
            try:
                sending(dns_response)
                sent = self.sock.sendto(dns_response, peer)
                event["dns_response_sent"] = sent == len(dns_response)
                event["response_sha256"] = hashlib.sha256(dns_response).hexdigest()
            except OSError as e:
                event["dns_response_sent"] = False
                event["dns_response_error"] = str(e)
                event["status"] = "failed"

        append_jsonl_event(self.events_log_path, event)

    @staticmethod
    def extract_udp_original_destination(
        ancdata,
    ) -> tuple[str | None, int | None]:
        for level, cmsg_type, cmsg_data in ancdata:
            if level == socket.SOL_IP and cmsg_type == IP_RECVORIGDSTADDR:
                ip, port = parse_sockaddr_in(cmsg_data)
                return str(ip), port

        return None, None

    @staticmethod
    def parse_peer(peer) -> tuple[str | None, int | None]:
        if not peer:
            return None, None

        if isinstance(peer, tuple) and len(peer) >= 2:
            return str(peer[0]), int(peer[1])

        return str(peer), None


async def run_transparent_logger(
    log_dir: str | Path,
    tcp_bind_ip: str = "127.0.0.1",
    tcp_bind_port: int = 40000,
    udp_bind_ip: str = "127.0.0.1",
    udp_bind_port: int = 40001,
) -> None:
    tcp_logger = TransparentTCPLogger(
        bind_ip=tcp_bind_ip,
        bind_port=tcp_bind_port,
        log_dir=log_dir,
    )

    udp_logger = TransparentUDPLogger(
        bind_ip=udp_bind_ip,
        bind_port=udp_bind_port,
        log_dir=log_dir,
    )

    tcp_server = None
    udp_lease = None
    try:
        tcp_server = await tcp_logger.start()
        udp_logger.start()
        runtime = current_runtime()
        if runtime is not None:
            udp_lease = runtime.call("listen")
        print("[+] Transparent logger is running. Press Ctrl+C to stop.")
        await tcp_server.serve_forever()
    finally:
        if udp_lease is not None:
            try:
                runtime.call("unlisten", key=udp_lease)
            except NetworkRuntimeError:
                pass
        if udp_logger.sock is not None:
            asyncio.get_running_loop().remove_reader(udp_logger.sock.fileno())
            udp_logger.sock.close()
        if tcp_server is not None:
            tcp_server.close()
            await tcp_server.wait_closed()
