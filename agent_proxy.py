#!/usr/bin/env python3
"""
Agent Proxy Bridge & CLI Wrapper
================================

Zero-dependency Python 3.9+ tool that:
1. Runs a local mixed HTTP / HTTPS CONNECT / SOCKS5 proxy backed by an
   encrypted TLS upstream tunnel (no external proxy binary required).
2. Wraps CLI coding agents (Antigravity `agy`, Claude Code `claude`,
   OpenAI `codex`, `cursor`, or any custom binary) so invocations inherit
   proxy settings and auto-start the local daemon.
3. Provides start / stop / status / list / wrap / unwrap / run / env commands.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import ipaddress
import json
import logging
import os
import shlex
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 17890

STATE_DIR = Path.home() / ".agent-proxy"
LEGACY_STATE_DIR = Path.home() / ".antigravity-vless-proxy"
PID_FILE = STATE_DIR / "proxy.pid"
STATE_FILE = STATE_DIR / "state.json"
LOG_FILE = STATE_DIR / "proxy.log"
CONFIG_FILE = STATE_DIR / "config.json"
WRAPPED_FILE = STATE_DIR / "wrapped.json"

logger = logging.getLogger("agent_proxy")


# ---------------------------------------------------------------------------
# Terminal styling
# ---------------------------------------------------------------------------


class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"


def color_mode() -> str:
    """Resolve color mode: explicit AGENT_PROXY_COLOR wins, then NO_COLOR/TERM."""
    mode = os.environ.get("AGENT_PROXY_COLOR", "").strip().lower()
    if mode in ("always", "never", "auto"):
        return mode
    if "NO_COLOR" in os.environ:
        return "never"
    if os.environ.get("TERM", "") == "dumb":
        return "never"
    return "auto"


def use_color(stream: Optional[object] = None) -> bool:
    mode = color_mode()
    if mode == "never":
        return False
    if mode == "always":
        return True
    target = stream if stream is not None else sys.stdout
    try:
        return bool(target.isatty())  # type: ignore[attr-defined]
    except Exception:
        return False


def paint(text: str, *codes: str, stream: Optional[object] = None) -> str:
    if not codes or not use_color(stream):
        return text
    return "".join(codes) + text + Style.RESET


def ok(text: str) -> str:
    return paint(text, Style.GREEN)


def warn(text: str) -> str:
    return paint(text, Style.YELLOW)


def fail(text: str) -> str:
    return paint(text, Style.RED)


def note(text: str) -> str:
    return paint(text, Style.DIM)


def strong(text: str) -> str:
    return paint(text, Style.BOLD)


def value(text: str) -> str:
    return paint(text, Style.CYAN)


# ---------------------------------------------------------------------------
# VLESS URI & Wire Protocol
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class VlessNode:
    raw_uri: str
    user_uuid: uuid.UUID
    host: str
    port: int
    encryption: str = "none"
    security: str = "tls"
    transport: str = "tcp"
    header_type: str = "none"
    sni: str = ""
    alpn: Tuple[str, ...] = ()
    allow_insecure: bool = False
    remark: str = ""

    @property
    def tls_server_name(self) -> str:
        return self.sni or self.host

    def display_label(self) -> str:
        name = f" [{self.remark}]" if self.remark else ""
        return f"{self.host}:{self.port} ({self.transport}/{self.security}){name}"


def parse_vless_uri(uri: str, force_insecure: bool = False) -> VlessNode:
    uri = uri.strip()
    parsed = urllib.parse.urlsplit(uri)
    if parsed.scheme.lower() != "vless":
        raise ValueError(f"Unsupported URI scheme {parsed.scheme!r}; expected 'vless://'")

    if not parsed.username:
        raise ValueError("VLESS URI is missing UUID")
    try:
        user_uuid = uuid.UUID(urllib.parse.unquote(parsed.username))
    except ValueError as exc:
        raise ValueError(f"Invalid VLESS UUID: {parsed.username!r}") from exc

    try:
        host = parsed.hostname
        explicit_port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid VLESS URI authority: {exc}") from exc
    if not host:
        raise ValueError("VLESS URI is missing server hostname")
    port = explicit_port or 443
    if not (1 <= port <= 65535):
        raise ValueError(f"Invalid VLESS port: {port}")

    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    def qget(key: str, default: str = "") -> str:
        vals = query.get(key)
        return vals[0].strip() if vals else default

    encryption = qget("encryption", "none").lower() or "none"
    security = qget("security", "none").lower() or "none"
    transport = qget("type", "tcp").lower() or "tcp"
    header_type = qget("headerType", "none").lower() or "none"
    sni = qget("sni", "") or qget("host", "") or host
    alpn_raw = qget("alpn", "")
    alpn = tuple(x.strip() for x in alpn_raw.split(",") if x.strip())
    allow_insecure = force_insecure or qget("allowInsecure", "0").lower() in ("1", "true", "yes") or qget(
        "insecure", "0"
    ).lower() in ("1", "true", "yes")
    remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""

    if encryption != "none":
        raise ValueError(f"Unsupported VLESS encryption={encryption!r}; only 'none' is supported")
    if transport != "tcp":
        raise ValueError(
            f"Built-in VLESS engine supports type='tcp' only (got type={transport!r}). "
            "For ws/grpc/xhttp, install xray or sing-box."
        )
    if security not in ("tls", "none"):
        raise ValueError(
            f"Built-in VLESS engine supports security='tls' or 'none' only (got security={security!r})."
        )
    if header_type not in ("none", ""):
        raise ValueError(f"Unsupported headerType={header_type!r}; only 'none' is supported")

    return VlessNode(
        raw_uri=uri,
        user_uuid=user_uuid,
        host=host,
        port=port,
        encryption=encryption,
        security=security,
        transport=transport,
        header_type=header_type,
        sni=sni,
        alpn=alpn,
        allow_insecure=allow_insecure,
        remark=remark,
    )


def build_vless_request_header(node: VlessNode, target_host: str, target_port: int, command: int = 0x01) -> bytes:
    """
    Build a VLESS v0 request header:
      [version: 1B = 0x00]
      [uuid: 16B]
      [addons_len: 1B = 0x00]
      [command: 1B = 0x01 (TCP)]
      [port: 2B big-endian]
      [addr_type: 1B] + [addr_bytes]
        0x01: IPv4 (4B)
        0x02: Domain (1B len + bytes)
        0x03: IPv6 (16B)
    """
    if not (1 <= target_port <= 65535):
        raise ValueError(f"Invalid target port: {target_port}")

    clean_host = target_host.strip("[]")
    addr_payload: bytes
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            addr_payload = b"\x01" + ip_obj.packed
        else:
            addr_payload = b"\x03" + ip_obj.packed
    except ValueError:
        domain_bytes = clean_host.encode("idna")
        if len(domain_bytes) > 255:
            raise ValueError(f"Target domain too long ({len(domain_bytes)} bytes): {clean_host}")
        addr_payload = bytes([0x02, len(domain_bytes)]) + domain_bytes

    return (
        b"\x00"
        + node.user_uuid.bytes
        + b"\x00"
        + bytes([command])
        + struct.pack("!H", target_port)
        + addr_payload
    )


def create_tls_context(node: VlessNode, cafile: Optional[str] = None) -> Optional[ssl.SSLContext]:
    if node.security != "tls":
        return None
    ctx = ssl.create_default_context(cafile=cafile)
    if node.allow_insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if node.alpn:
        try:
            ctx.set_alpn_protocols(list(node.alpn))
        except NotImplementedError:
            pass
    return ctx


def _tune_socket(writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass


def _is_direct_host(host: str) -> bool:
    h = host.strip("[]").lower().rstrip(".")
    if h in ("localhost", "127.0.0.1", "::1") or h.endswith(".local"):
        return True
    try:
        ip_obj = ipaddress.ip_address(h)
        return ip_obj.is_loopback
    except ValueError:
        return False


async def _close_writer(writer: Optional[asyncio.StreamWriter]) -> None:
    if writer is None:
        return
    try:
        if not writer.is_closing():
            writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except Exception:
        pass


def _install_ssl_shutdown_filter(loop: asyncio.AbstractEventLoop) -> None:
    """Suppress harmless CPython 3.9 SSLProtocol close_notify race on shutdown."""
    default_handler = loop.default_exception_handler

    def handler(ev_loop: asyncio.AbstractEventLoop, context: Dict[str, Any]) -> None:
        msg = str(context.get("message", ""))
        exc = context.get("exception")
        if "Fatal error on SSL transport" in msg and isinstance(exc, (OSError, RuntimeError)):
            return
        default_handler(context)

    loop.set_exception_handler(handler)


# ---------------------------------------------------------------------------
# Local Mixed HTTP / HTTPS CONNECT / SOCKS5 Proxy Server
# ---------------------------------------------------------------------------


SOCKS5_REPLY_SUCCESS = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
SOCKS5_REPLY_GENERAL_FAILURE = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
SOCKS5_REPLY_COMMAND_UNSUPPORTED = b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"
SOCKS5_REPLY_ADDRESS_UNSUPPORTED = b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00"


async def _reply_http_status(writer: asyncio.StreamWriter, status_line: str, message: str = "") -> None:
    body = (message + "\n").encode("utf-8") if message else b""
    headers = [
        f"HTTP/1.1 {status_line}",
        "Content-Type: text/plain; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("latin-1") + body)
    await writer.drain()


class VlessLocalProxyServer:
    def __init__(
        self,
        node: VlessNode,
        listen_host: str = DEFAULT_LISTEN_HOST,
        listen_port: int = DEFAULT_LISTEN_PORT,
        connect_timeout: float = 15.0,
        cafile: Optional[str] = None,
    ) -> None:
        self.node = node
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.connect_timeout = connect_timeout
        self.ssl_ctx = create_tls_context(node, cafile=cafile)
        self._server: Optional[asyncio.AbstractServer] = None
        self._client_tasks: Set[asyncio.Task] = set()

    @property
    def bound_port(self) -> int:
        sockets = getattr(self._server, "sockets", None) if self._server else None
        if sockets:
            return int(sockets[0].getsockname()[1])
        return self.listen_port

    async def start(self) -> None:
        _install_ssl_shutdown_filter(asyncio.get_running_loop())
        self._server = await asyncio.start_server(
            self._accept_client,
            host=self.listen_host,
            port=self.listen_port,
            reuse_address=True,
        )
        logger.info(
            "Local mixed proxy (HTTP/HTTPS/SOCKS5) listening on %s:%d -> VLESS %s",
            self.listen_host,
            self.bound_port,
            self.node.display_label(),
        )

    def _accept_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.create_task(self._handle_client(client_reader, client_writer))
        self._client_tasks.add(task)
        task.add_done_callback(self._client_tasks.discard)

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._client_tasks:
            tasks = list(self._client_tasks)
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        # Allow Python 3.9 SSLProtocol close callbacks to settle before loop closes
        await asyncio.sleep(0.25)

    async def _open_upstream(
        self,
        target_host: str,
        target_port: int,
        initial_payload: bytes = b"",
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, bool]:
        """
        Opens either a direct connection (for loopback hosts) or a VLESS tunnel.
        Returns (reader, writer, is_vless).
        """
        if _is_direct_host(target_host):
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=self.connect_timeout,
            )
            _tune_socket(writer)
            if initial_payload:
                writer.write(initial_payload)
                await writer.drain()
            return reader, writer, False

        connect_kwargs: Dict[str, Any] = {}
        if self.ssl_ctx is not None:
            connect_kwargs["ssl"] = self.ssl_ctx
            connect_kwargs["server_hostname"] = self.node.tls_server_name

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.node.host, self.node.port, **connect_kwargs),
            timeout=self.connect_timeout,
        )
        _tune_socket(writer)

        vless_header = build_vless_request_header(self.node, target_host, target_port)
        writer.write(vless_header + initial_payload)
        await writer.drain()
        return reader, writer, True

    async def _pipe_client_to_remote(
        self,
        client_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
    ) -> None:
        try:
            while True:
                chunk = await client_reader.read(65536)
                if not chunk:
                    break
                remote_writer.write(chunk)
                await remote_writer.drain()
            if remote_writer.can_write_eof():
                remote_writer.write_eof()
        except (asyncio.CancelledError, OSError):
            pass

    async def _pipe_remote_to_client(
        self,
        remote_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        strip_vless_header: bool,
    ) -> None:
        try:
            if strip_vless_header:
                header = await remote_reader.readexactly(2)
                resp_ver, addons_len = header[0], header[1]
                if resp_ver != 0:
                    raise ValueError(f"Unexpected VLESS response version: {resp_ver}")
                if addons_len > 0:
                    await remote_reader.readexactly(addons_len)

            while True:
                chunk = await remote_reader.read(65536)
                if not chunk:
                    break
                client_writer.write(chunk)
                await client_writer.drain()
            if client_writer.can_write_eof():
                client_writer.write_eof()
        except (asyncio.CancelledError, OSError):
            pass
        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            logger.debug("Upstream read error: %s", exc)

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        is_vless: bool,
    ) -> None:
        t1 = asyncio.create_task(self._pipe_client_to_remote(client_reader, remote_writer))
        t2 = asyncio.create_task(self._pipe_remote_to_client(remote_reader, client_writer, is_vless))
        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        # Allow a brief moment for the opposite direction to flush cleanly if it finishes too
        if pending:
            _, still_pending = await asyncio.wait(pending, timeout=2.0)
            for task in still_pending:
                task.cancel()
            if still_pending:
                await asyncio.gather(*still_pending, return_exceptions=True)
        await asyncio.gather(*done, return_exceptions=True)

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        _tune_socket(client_writer)
        remote_writer: Optional[asyncio.StreamWriter] = None
        try:
            first_byte = await asyncio.wait_for(client_reader.read(1), timeout=30.0)
            if not first_byte:
                return
            if first_byte == b"\x05":
                remote_writer = await self._handle_socks5(client_reader, client_writer)
            else:
                remote_writer = await self._handle_http(first_byte, client_reader, client_writer)
        except asyncio.TimeoutError:
            logger.debug("Client handshake timed out")
        except Exception as exc:
            logger.debug("Connection error: %s", exc)
        finally:
            await _close_writer(remote_writer)
            await _close_writer(client_writer)

    async def _handle_socks5(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> Optional[asyncio.StreamWriter]:
        # Already consumed version byte 0x05
        nmethods_b = await client_reader.readexactly(1)
        nmethods = nmethods_b[0]
        methods = await client_reader.readexactly(nmethods)
        if not methods or 0x00 not in methods:
            client_writer.write(b"\x05\xff")
            await client_writer.drain()
            return None
        # Select NO AUTH (0x00)
        client_writer.write(b"\x05\x00")
        await client_writer.drain()

        # Request: VER CMD RSV ATYP DST.ADDR DST.PORT
        req_head = await client_reader.readexactly(4)
        ver, cmd, _rsv, atyp = req_head
        if ver != 0x05:
            return None
        if cmd != 0x01:  # Only TCP CONNECT supported
            client_writer.write(SOCKS5_REPLY_COMMAND_UNSUPPORTED)
            await client_writer.drain()
            return None

        if atyp == 0x01:  # IPv4
            target_host = socket.inet_ntop(socket.AF_INET, await client_reader.readexactly(4))
        elif atyp == 0x03:  # Domain
            dlen = (await client_reader.readexactly(1))[0]
            if dlen == 0:
                client_writer.write(SOCKS5_REPLY_ADDRESS_UNSUPPORTED)
                await client_writer.drain()
                return None
            target_host = (await client_reader.readexactly(dlen)).decode("utf-8", errors="replace")
        elif atyp == 0x04:  # IPv6
            target_host = socket.inet_ntop(socket.AF_INET6, await client_reader.readexactly(16))
        else:
            client_writer.write(SOCKS5_REPLY_ADDRESS_UNSUPPORTED)
            await client_writer.drain()
            return None

        target_port = struct.unpack("!H", await client_reader.readexactly(2))[0]
        logger.debug("SOCKS5 CONNECT %s:%d", target_host, target_port)

        try:
            remote_reader, remote_writer, is_vless = await self._open_upstream(target_host, target_port)
        except Exception as exc:
            logger.warning("SOCKS5 upstream failed for %s:%d: %s", target_host, target_port, exc)
            client_writer.write(SOCKS5_REPLY_GENERAL_FAILURE)
            await client_writer.drain()
            return None

        # Reply SUCCEEDED immediately (VLESS response header arrives lazily after client sends payload)
        client_writer.write(SOCKS5_REPLY_SUCCESS)
        await client_writer.drain()

        await self._relay(client_reader, client_writer, remote_reader, remote_writer, is_vless)
        return remote_writer

    async def _handle_http(
        self,
        first_byte: bytes,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> Optional[asyncio.StreamWriter]:
        try:
            rest_head = await asyncio.wait_for(client_reader.readuntil(b"\r\n\r\n"), timeout=30.0)
        except asyncio.TimeoutError:
            await _reply_http_status(client_writer, "408 Request Timeout", "Timed out reading request headers.")
            return None
        except asyncio.LimitOverrunError:
            await _reply_http_status(client_writer, "431 Request Header Fields Too Large")
            return None
        except asyncio.IncompleteReadError:
            return None

        raw_header = first_byte + rest_head
        header_text = raw_header.decode("latin-1")
        lines = header_text.split("\r\n")
        if not lines:
            return None

        parts = lines[0].split(" ")
        if len(parts) < 3:
            await _reply_http_status(client_writer, "400 Bad Request", "Malformed HTTP request line.")
            return None

        method, target, http_version = parts[0].upper(), parts[1], parts[2]
        header_lines = [line for line in lines[1:] if line]

        if method == "CONNECT":
            try:
                target_host, target_port = _parse_host_port(target, default_port=443)
            except ValueError as exc:
                await _reply_http_status(client_writer, "400 Bad Request", str(exc))
                return None
            logger.debug("HTTP CONNECT %s:%d", target_host, target_port)
            try:
                remote_reader, remote_writer, is_vless = await self._open_upstream(target_host, target_port)
            except Exception as exc:
                logger.warning("HTTP CONNECT upstream failed for %s:%d: %s", target_host, target_port, exc)
                await _reply_http_status(client_writer, "502 Bad Gateway", "Upstream connection failed.")
                return None

            client_writer.write(f"{http_version} 200 Connection Established\r\n\r\n".encode("latin-1"))
            await client_writer.drain()

            await self._relay(client_reader, client_writer, remote_reader, remote_writer, is_vless)
            return remote_writer

        # Plain HTTP request forwarding
        if target.startswith("https://"):
            await _reply_http_status(
                client_writer,
                "400 Bad Request",
                "Absolute https:// requests are not supported; use CONNECT instead.",
            )
            return None
        if target.startswith("http://"):
            parsed_url = urllib.parse.urlsplit(target)
            target_host = parsed_url.hostname or ""
            target_port = parsed_url.port or 80
            path = parsed_url.path or "/"
            if parsed_url.query:
                path = f"{path}?{parsed_url.query}"
        else:
            host_header = ""
            for line in header_lines:
                if line.lower().startswith("host:"):
                    host_header = line.split(":", 1)[1].strip()
                    break
            if not host_header:
                await _reply_http_status(client_writer, "400 Bad Request", "Missing Host header.")
                return None
            try:
                target_host, target_port = _parse_host_port(host_header, default_port=80)
            except ValueError as exc:
                await _reply_http_status(client_writer, "400 Bad Request", str(exc))
                return None
            path = target

        if not target_host:
            await _reply_http_status(client_writer, "400 Bad Request", "Missing target host.")
            return None

        logger.debug("HTTP %s %s:%d%s", method, target_host, target_port, path)

        rebuilt_headers = [f"{method} {path} {http_version}"]
        has_host = False
        for line in header_lines:
            key = line.split(":", 1)[0].strip().lower()
            if key in ("proxy-connection", "proxy-authorization"):
                continue
            if key == "host":
                has_host = True
            rebuilt_headers.append(line)
        if not has_host:
            host_val = f"[{target_host}]" if ":" in target_host else target_host
            if target_port != 80:
                host_val = f"{host_val}:{target_port}"
            rebuilt_headers.append(f"Host: {host_val}")

        initial_payload = ("\r\n".join(rebuilt_headers) + "\r\n\r\n").encode("latin-1")

        try:
            remote_reader, remote_writer, is_vless = await self._open_upstream(
                target_host, target_port, initial_payload=initial_payload
            )
        except Exception as exc:
            logger.warning("HTTP upstream failed for %s:%d: %s", target_host, target_port, exc)
            await _reply_http_status(client_writer, "502 Bad Gateway", "Upstream connection failed.")
            return None

        await self._relay(client_reader, client_writer, remote_reader, remote_writer, is_vless)
        return remote_writer


def _parse_host_port(authority: str, default_port: int) -> Tuple[str, int]:
    """Parse `host[:port]` or `[ipv6][:port]`; raise ValueError on malformed input."""
    authority = authority.strip()
    if not authority:
        raise ValueError("Empty host authority")
    if authority.startswith("["):
        end_bracket = authority.find("]")
        if end_bracket == -1:
            raise ValueError(f"Malformed IPv6 authority: {authority!r}")
        host = authority[1:end_bracket]
        rest = authority[end_bracket + 1 :]
        if rest and not rest.startswith(":"):
            raise ValueError(f"Malformed authority: {authority!r}")
        port_str = rest[1:] if rest else ""
    elif authority.count(":") > 1:
        # Bare IPv6 address without brackets and without a port
        return authority, default_port
    elif ":" in authority:
        host, port_str = authority.rsplit(":", 1)
    else:
        return authority, default_port

    if not host:
        raise ValueError(f"Missing host in authority: {authority!r}")
    if not port_str:
        return host, default_port
    try:
        port = int(port_str)
    except ValueError as exc:
        raise ValueError(f"Invalid port in authority {authority!r}: {port_str!r}") from exc
    if not (1 <= port <= 65535):
        raise ValueError(f"Port out of range in authority {authority!r}: {port}")
    return host, port


# ---------------------------------------------------------------------------
# Runtime State, Config & Daemon Control
# ---------------------------------------------------------------------------


def load_saved_uri() -> Optional[str]:
    for cfg in (CONFIG_FILE, LEGACY_STATE_DIR / "config.json"):
        if cfg.exists():
            try:
                data = json.loads(cfg.read_text(encoding="utf-8"))
                for key in ("upstream_uri", "vless_uri"):
                    uri = data.get(key)
                    if isinstance(uri, str) and uri.strip():
                        return uri.strip()
            except Exception:
                pass
    return None


def prompt_upstream_uri(force_insecure: bool = False, save: bool = True) -> str:
    print(warn("No upstream proxy node configured."))
    print("Enter a VLESS URI, for example:")
    print("  " + value("vless://<uuid>@<host>:<port>?security=tls&type=tcp#remark"))
    while True:
        try:
            entered = input(strong("Enter proxy node URI: ")).strip()
        except (EOFError, KeyboardInterrupt) as exc:
            raise ValueError("Cancelled entering proxy node URI.") from exc
        if not entered:
            print(fail("Proxy node URI cannot be empty; please try again."), file=sys.stderr)
            continue
        try:
            parse_vless_uri(entered, force_insecure=force_insecure)
        except ValueError as exc:
            print(fail(f"Invalid node URI: {exc}. Please try again."), file=sys.stderr)
            continue
        if save:
            save_default_uri(entered)
            print_saved_config()
        return entered


def resolve_upstream_uri(
    cli_uri: Optional[str],
    *,
    prompt_if_missing: bool = False,
    save_prompted: bool = True,
    force_insecure: bool = False,
) -> str:
    if cli_uri and cli_uri.strip():
        return cli_uri.strip()
    for env_key in ("AGENT_PROXY_URI", "VLESS_URI"):
        env_uri = os.environ.get(env_key, "").strip()
        if env_uri:
            return env_uri
    saved = load_saved_uri()
    if saved:
        return saved
    if prompt_if_missing and sys.stdin.isatty():
        return prompt_upstream_uri(force_insecure=force_insecure, save=save_prompted)
    raise ValueError(
        "No upstream proxy node configured. Provide one using any of the following:\n"
        "  1. Interactive: agent-proxy start -d (prompts and saves)\n"
        "  2. CLI flag   : agent-proxy start -d --save --uri 'vless://<uuid>@<host>:<port>?security=tls&type=tcp'\n"
        "  3. Env var    : AGENT_PROXY_URI='vless://...'\n"
        f"  4. Config file: {CONFIG_FILE}"
    )


resolve_vless_uri = resolve_upstream_uri


def _atomic_write_text(path: Path, content: str) -> None:
    """Write content to path atomically (temp file + rename) to avoid corruption."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _write_json(path: Path, data: object) -> None:
    _atomic_write_text(path, json.dumps(data, indent=2) + "\n")


def save_default_uri(uri: str) -> None:
    _write_json(CONFIG_FILE, {"upstream_uri": uri})


def print_saved_config() -> None:
    print(ok("Saved node config: ") + value(str(CONFIG_FILE)))


def _as_int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def read_running_state() -> Optional[Dict[str, Any]]:
    if not PID_FILE.exists():
        return None
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except Exception:
        return None
    if not _pid_alive(pid):
        return None
    state: Dict[str, Any] = {"pid": pid}
    if STATE_FILE.exists():
        try:
            state.update(json.loads(STATE_FILE.read_text(encoding="utf-8")))
        except Exception:
            pass
    return state


def upstream_identity(uri: str) -> str:
    """Short, non-reversible fingerprint used to detect node changes."""
    return hashlib.sha256(uri.strip().encode("utf-8")).hexdigest()[:12]


def write_running_state(pid: int, host: str, port: int, node: VlessNode) -> None:
    _atomic_write_text(PID_FILE, f"{pid}\n")
    _write_json(
        STATE_FILE,
        {
            "pid": pid,
            "listen_host": host,
            "listen_port": port,
            "node": node.display_label(),
            "upstream_id": upstream_identity(node.raw_uri),
            "started_at": int(time.time()),
        },
    )


def clear_running_state() -> None:
    for p in (PID_FILE, STATE_FILE):
        try:
            p.unlink()
        except FileNotFoundError:
            pass


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Poll a TCP port until it accepts connections or the timeout expires."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)


def start_daemon(uri: str, host: str, port: int, insecure: bool, verbose: bool) -> Dict[str, Any]:
    existing = read_running_state()
    if existing:
        same_endpoint = (
            existing.get("listen_host") == host
            and _as_int(existing.get("listen_port"), -1) == port
            and _wait_for_port(host, port, timeout=0.5)
        )
        known_identity = existing.get("upstream_id")
        same_upstream = known_identity is None or known_identity == upstream_identity(uri)
        if same_endpoint and same_upstream:
            return existing
        # Endpoint or upstream node changed; stop the previous daemon first.
        stop_daemon()

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "start",
        "--uri",
        uri,
        "--host",
        host,
        "--port",
        str(port),
    ]
    if insecure:
        cmd.append("--insecure")
    if verbose:
        cmd.append("--verbose")

    with open(LOG_FILE, "ab") as log_f:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=log_f,
            stderr=log_f,
            start_new_session=True,
        )

    if not _wait_for_port(host, port, timeout=5.0):
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        tail = ""
        if LOG_FILE.exists():
            tail = LOG_FILE.read_text(encoding="utf-8", errors="replace")[-1000:].strip()
        detail = f"\nLog tail:\n{tail}" if tail else ""
        raise RuntimeError(
            f"Proxy daemon failed to start on {host}:{port}. See {LOG_FILE} for details.{detail}"
        )

    state = read_running_state()
    if state:
        return state
    return {"pid": proc.pid, "listen_host": host, "listen_port": port}


def stop_daemon() -> bool:
    state = read_running_state()
    if not state:
        clear_running_state()
        return False
    pid = int(state["pid"])
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        clear_running_state()
        return False

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            clear_running_state()
            return True
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    kill_deadline = time.monotonic() + 2.0
    while time.monotonic() < kill_deadline and _pid_alive(pid):
        time.sleep(0.05)
    clear_running_state()
    return True


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------


class _ColorLogFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG: Style.DIM,
        logging.INFO: Style.GREEN,
        logging.WARNING: Style.YELLOW,
        logging.ERROR: Style.RED,
        logging.CRITICAL: Style.RED,
    }

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        code = self.LEVEL_COLORS.get(record.levelno)
        return paint(message, code, stream=sys.stderr) if code else message


def _setup_logging(verbose: bool) -> None:
    handler = logging.StreamHandler(sys.stderr)
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    if use_color(sys.stderr):
        handler.setFormatter(_ColorLogFormatter(fmt, datefmt="%H:%M:%S"))
    else:
        handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        handlers=[handler],
    )


async def _run_server_foreground(node: VlessNode, host: str, port: int) -> None:
    server = VlessLocalProxyServer(node=node, listen_host=host, listen_port=port)
    await server.start()
    write_running_state(os.getpid(), host, server.bound_port, node)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    try:
        await stop_event.wait()
    finally:
        logger.info("Shutting down local proxy...")
        await server.stop()
        clear_running_state()


def print_proxy_details(host: str, port: int, upstream: str) -> None:
    print(f"  {strong('HTTP/HTTPS')} : {value(f'http://{host}:{port}')}")
    print(f"  {strong('SOCKS5')}     : {value(f'socks5h://{host}:{port}')}")
    print(f"  {strong('Upstream')}   : {upstream}")
    print(f"  {strong('Log file')}   : {note(str(LOG_FILE))}")


def cmd_start(args: argparse.Namespace) -> int:
    uri = resolve_upstream_uri(
        args.uri,
        prompt_if_missing=True,
        save_prompted=True,
        force_insecure=args.insecure,
    )
    node = parse_vless_uri(uri, force_insecure=args.insecure)
    if args.save:
        save_default_uri(uri)

    if args.daemon:
        state = start_daemon(uri, args.host, args.port, args.insecure, args.verbose)
        print(ok(f"Proxy started in background (PID {state['pid']})."))
        print_proxy_details(args.host, args.port, node.display_label())
        print(note(f"Tip: run `agent-proxy wrap` to make coding agents use this proxy automatically."))
        return 0

    _setup_logging(args.verbose)
    try:
        asyncio.run(_run_server_foreground(node, args.host, args.port))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_stop(_args: argparse.Namespace) -> int:
    stopped = stop_daemon()
    if stopped:
        print(ok("Proxy daemon stopped."))
    else:
        print(note("Proxy daemon is not running."))
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    state = read_running_state()
    if not state:
        print(f"{strong('Status')}: {fail('STOPPED')}")
        try:
            configured = resolve_upstream_uri(None)
            print(f"{strong('Default upstream')}: {parse_vless_uri(configured).display_label()}")
        except ValueError:
            print(f"{strong('Default upstream')}: {note('(not configured)')}")
            print(note("Configure it with: agent-proxy start -d --save --uri 'vless://...'"))
        else:
            print(note("Start it with: agent-proxy start -d"))
        return 1
    host = str(state.get("listen_host") or DEFAULT_LISTEN_HOST)
    port = _as_int(state.get("listen_port"), DEFAULT_LISTEN_PORT)
    reachable = _wait_for_port(host, port, timeout=0.5)
    status_text = ok("RUNNING") if reachable else warn("STARTING/UNREACHABLE")
    print(f"{strong('Status')}     : {status_text} (PID {state['pid']})")
    print_proxy_details(host, port, str(state.get("node", "unknown")))
    return 0


# ---------------------------------------------------------------------------
# Multi-Agent CLI Wrapper
# ---------------------------------------------------------------------------

WRAPPER_MARKER = "# agent-proxy-wrapper v2"
LEGACY_WRAPPER_MARKERS = (WRAPPER_MARKER, "# agy-proxy-wrapper v1")
LOCAL_BIN = Path.home() / ".local" / "bin"
DEFAULT_NO_PROXY = "localhost,127.0.0.1,::1,.local"
INTRANET_NO_PROXY = (
    "localhost,127.0.0.1,::1,.local,"
    ".pdd.net,.pdd-test.net,.ddmcsup.com,"
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
)


@dataclasses.dataclass(frozen=True)
class AgentProfile:
    name: str
    display_name: str
    bin_names: Tuple[str, ...]
    extra_paths: Tuple[Path, ...]
    process_names: Tuple[str, ...]


def _build_agent_profiles() -> Dict[str, AgentProfile]:
    home = Path.home()
    return {
        "agy": AgentProfile(
            name="agy",
            display_name="Antigravity (agy)",
            bin_names=("agy",),
            extra_paths=(
                home / ".local" / "bin" / "agy",
                home / ".gemini" / "bin" / "agy",
            ),
            process_names=("agy", "agy.real"),
        ),
        "claude": AgentProfile(
            name="claude",
            display_name="Claude Code (claude)",
            bin_names=("claude",),
            extra_paths=(
                home / ".local" / "bin" / "claude",
                home / ".claude" / "local" / "claude",
                Path("/opt/homebrew/bin/claude"),
                Path("/usr/local/bin/claude"),
                home / ".npm-global" / "bin" / "claude",
                home / ".volta" / "bin" / "claude",
                home / ".asdf" / "shims" / "claude",
            ),
            process_names=("claude", "claude.real"),
        ),
        "codex": AgentProfile(
            name="codex",
            display_name="OpenAI Codex (codex)",
            bin_names=("codex",),
            extra_paths=(
                home / ".local" / "bin" / "codex",
                Path("/opt/homebrew/bin/codex"),
                Path("/usr/local/bin/codex"),
                home / ".npm-global" / "bin" / "codex",
                home / ".volta" / "bin" / "codex",
                home / ".cargo" / "bin" / "codex",
                home / ".asdf" / "shims" / "codex",
            ),
            process_names=("codex", "codex.real"),
        ),
        "cursor": AgentProfile(
            name="cursor",
            display_name="Cursor (cursor)",
            bin_names=("cursor",),
            extra_paths=(
                home / ".local" / "bin" / "cursor",
                Path("/usr/local/bin/cursor"),
                Path("/opt/homebrew/bin/cursor"),
            ),
            process_names=("cursor", "cursor.real"),
        ),
    }


AGENT_PROFILES: Dict[str, AgentProfile] = _build_agent_profiles()
AGENT_ALIASES: Dict[str, str] = {
    "antigravity": "agy",
    "agy": "agy",
    "claude": "claude",
    "claude-code": "claude",
    "codex": "codex",
    "openai-codex": "codex",
    "cursor": "cursor",
}


def _resolve_agent_names(names: Optional[Sequence[str]]) -> List[str]:
    if not names:
        return list(AGENT_PROFILES.keys())
    resolved: List[str] = []
    for raw in names:
        key = raw.strip().lower()
        if key == "all":
            for name in AGENT_PROFILES:
                if name not in resolved:
                    resolved.append(name)
            continue
        canonical = AGENT_ALIASES.get(key)
        if not canonical:
            supported = ", ".join(AGENT_PROFILES.keys())
            raise ValueError(f"Unknown agent {raw!r}. Supported: {supported} (or 'all')")
        if canonical not in resolved:
            resolved.append(canonical)
    return resolved


def _dedupe_paths(paths: Iterable[Path]) -> List[Path]:
    """Expand user dirs, normalize to absolute paths and drop duplicates."""
    result: List[Path] = []
    seen: Set[str] = set()
    for path in paths:
        norm = os.path.abspath(os.path.expanduser(str(path)))
        if norm not in seen:
            seen.add(norm)
            result.append(Path(norm))
    return result


def _path_exists_entry(path: Path) -> bool:
    try:
        return (path.is_symlink() or path.exists()) and not path.is_dir()
    except OSError:
        return False


def _path_exists_safe(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _is_our_wrapper(target: Path) -> bool:
    try:
        if target.is_symlink() or not target.exists() or target.is_dir():
            return False
        head = target.read_text(encoding="utf-8", errors="ignore")[:300]
    except OSError:
        return False
    return any(marker in head for marker in LEGACY_WRAPPER_MARKERS)


def _discover_profile_bins(profile: AgentProfile) -> List[Path]:
    candidates: List[Path] = []
    seen_abs: Set[str] = set()

    def add(p: Path) -> None:
        if not _path_exists_entry(p):
            return
        norm = os.path.abspath(str(p))
        if norm not in seen_abs:
            seen_abs.add(norm)
            candidates.append(Path(norm))

    for bin_name in profile.bin_names:
        found = shutil.which(bin_name)
        if found:
            add(Path(found))
    for extra in profile.extra_paths:
        add(extra)

    # Avoid wrapping both a symlink and the resolved file it directly points to
    symlink_targets: Set[str] = set()
    for p in candidates:
        if p.is_symlink():
            try:
                symlink_targets.add(str(p.resolve()))
            except OSError:
                pass
    return [p for p in candidates if p.is_symlink() or str(p) not in symlink_targets]


def _load_wrapped_registry() -> List[str]:
    if not _path_exists_safe(WRAPPED_FILE):
        return []
    try:
        data = json.loads(WRAPPED_FILE.read_text(encoding="utf-8"))
        paths = data.get("wrapped", [])
        if isinstance(paths, list):
            return [str(p) for p in paths if isinstance(p, str)]
    except Exception:
        pass
    return []


def _save_wrapped_registry(paths: Iterable[str]) -> None:
    unique = sorted({os.path.abspath(p) for p in paths})
    _write_json(WRAPPED_FILE, {"wrapped": unique})


def _record_wrapped_path(target: Path) -> None:
    current = _load_wrapped_registry()
    current.append(str(target))
    _save_wrapped_registry(current)


def _forget_wrapped_path(target: Path) -> None:
    norm = os.path.abspath(str(target))
    current = [p for p in _load_wrapped_registry() if os.path.abspath(p) != norm]
    if WRAPPED_FILE.exists() or current:
        _save_wrapped_registry(current)


def _proxy_env(host: str, port: int, no_proxy: Optional[str] = None) -> Dict[str, str]:
    url = f"http://{host}:{port}"
    bypass = no_proxy if no_proxy is not None else os.environ.get("NO_PROXY") or DEFAULT_NO_PROXY
    return {
        "HTTP_PROXY": url,
        "HTTPS_PROXY": url,
        "http_proxy": url,
        "https_proxy": url,
        "ALL_PROXY": f"socks5h://{host}:{port}",
        "all_proxy": f"socks5h://{host}:{port}",
        "NO_PROXY": bypass,
        "no_proxy": bypass,
        "NODE_USE_ENV_PROXY": "1",
    }


def _wrapper_script(bin_name: str, host: str, port: int) -> str:
    """Render the POSIX sh wrapper that injects proxy env vars before exec'ing the real CLI."""
    app = _escape_double_quoted(str(Path(__file__).resolve()))
    py = _escape_double_quoted(sys.executable or "/usr/bin/python3")
    name = _escape_double_quoted(bin_name)
    host_q = _escape_double_quoted(host)
    port_q = _escape_double_quoted(str(port))
    return f'''#!/bin/sh
{WRAPPER_MARKER}
# Generated by `agent-proxy wrap`: injects local proxy env vars before launching `{bin_name}`.
# Restore the original binary with: agent-proxy unwrap
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_DIR="$SELF_DIR"
BIN_NAME="{name}"
PY="{py}"
APP="{app}"
HOST="{host_q}"
PORT="{port_q}"
PROXY="http://$HOST:$PORT"

port_open() {{
  if command -v nc >/dev/null 2>&1; then
    nc -z -w 1 "$HOST" "$PORT" >/dev/null 2>&1 && return 0
    return 1
  fi
  "$PY" -c 'import socket,sys;s=socket.socket();s.settimeout(1);sys.exit(0 if s.connect_ex((sys.argv[1],int(sys.argv[2])))==0 else 1)' \
    "$HOST" "$PORT" >/dev/null 2>&1
}}

# 1) Locate the real entry point: the original file/symlink, renamed to ${{BIN_NAME}}.real on wrap.
if [ -x "$BIN_DIR/${{BIN_NAME}}.real" ] || [ -L "$BIN_DIR/${{BIN_NAME}}.real" ]; then
  REAL="$BIN_DIR/${{BIN_NAME}}.real"
else
  REAL=""
  OLD_IFS=$IFS
  IFS=:
  for d in $PATH; do
    [ "$d" = "$BIN_DIR" ] && continue
    if [ -x "$d/$BIN_NAME" ] && [ ! -d "$d/$BIN_NAME" ]; then REAL="$d/$BIN_NAME"; break; fi
  done
  IFS=$OLD_IFS
fi
if [ -z "$REAL" ]; then
  echo "agent-proxy: could not find the real $BIN_NAME binary (expected $BIN_DIR/${{BIN_NAME}}.real)." >&2
  echo "agent-proxy: run 'agent-proxy wrap' again to repair the wrapper, or 'agent-proxy unwrap' to restore." >&2
  exit 127
fi

# 2) Start the local proxy daemon if it is not listening yet (wait up to ~5s).
if ! port_open; then
  "$PY" "$APP" start -d --host "$HOST" --port "$PORT" >/dev/null 2>&1 &
  i=0
  while [ "$i" -lt 50 ]; do
    port_open && break
    i=$((i + 1))
    sleep 0.1
  done
fi

# 3) Inject proxy env vars (compatible with Go/Node/Python/Rust CLIs). If the proxy
#    is still unavailable, keep going without it so the CLI itself still works.
if port_open; then
  export HTTP_PROXY="$PROXY"  HTTPS_PROXY="$PROXY"
  export http_proxy="$PROXY"  https_proxy="$PROXY"
  export ALL_PROXY="socks5h://$HOST:$PORT"  all_proxy="socks5h://$HOST:$PORT"
  export NO_PROXY="${{NO_PROXY:-{DEFAULT_NO_PROXY}}}"
  export no_proxy="${{no_proxy:-{DEFAULT_NO_PROXY}}}"
  export NODE_USE_ENV_PROXY=1
else
  echo "agent-proxy: warning: local proxy $HOST:$PORT is unavailable; starting $BIN_NAME without proxy." >&2
fi

exec "$REAL" "$@"
'''


def _wrap_one(target: Path, host: str, port: int) -> bool:
    if not _path_exists_entry(target):
        return False
    real = target.with_name(target.name + ".real")
    if not _is_our_wrapper(target):
        if real.is_symlink() or real.exists():
            real.unlink()
        os.replace(target, real)
        print(f"  {note('Preserved original binary:')} {target} -> {real.name}")
    target.write_text(_wrapper_script(target.name, host, port), encoding="utf-8")
    os.chmod(target, 0o755)
    _record_wrapped_path(target)
    print(f"  {ok('Wrapped:')} {target}")
    return True


def _unwrap_one(target: Path) -> bool:
    real = target.with_name(target.name + ".real")
    if _is_our_wrapper(target) and (real.is_symlink() or real.exists()):
        os.replace(real, target)
        _forget_wrapped_path(target)
        print(f"  {ok('Restored:')} {target}")
        return True
    return False


def _running_agent_pids(process_names: Iterable[str]) -> List[int]:
    names = set(process_names)
    if not names:
        return []
    try:
        out = subprocess.run(["ps", "-Ao", "pid=,command="],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return []
    pids: List[int] = []
    me = os.getpid()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        pid_s, _, cmd = line.partition(" ")
        try:
            pid = int(pid_s)
        except ValueError:
            continue
        if pid == me:
            continue
        argv = cmd.split()
        if not argv:
            continue
        exe = Path(argv[0]).name
        if exe in names:
            pids.append(pid)
    return pids


def _restart_agent_processes(process_names: Iterable[str], timeout: float = 5.0) -> int:
    pids = _running_agent_pids(process_names)
    if not pids:
        print(note("  No running target processes need to be restarted."))
        return 0
    print(f"  {strong('Restarting processes:')} {pids}")
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            print(warn(f"  Skipped process {pid} (permission denied)"))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(_pid_alive(p) for p in pids):
            break
        time.sleep(0.2)
    for pid in pids:
        if _pid_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    print(ok("  Stopped old processes; the next invocation or IDE session will automatically use the proxy."))
    return 0


def _ensure_proxy_running(host: str, port: int, uri: Optional[str] = None, insecure: bool = False) -> None:
    if _wait_for_port(host, port, timeout=0.25):
        return
    resolved_uri = resolve_upstream_uri(
        uri,
        prompt_if_missing=True,
        save_prompted=True,
        force_insecure=insecure,
    )
    parse_vless_uri(resolved_uri, force_insecure=insecure)
    start_daemon(resolved_uri, host, port, insecure=insecure, verbose=False)


def cmd_list(_args: argparse.Namespace) -> int:
    print(strong("Supported Coding Agents:"))
    discovered = {name: _discover_profile_bins(profile) for name, profile in AGENT_PROFILES.items()}
    wrapped_count = 0
    for name, profile in AGENT_PROFILES.items():
        bins = discovered[name]
        if bins:
            parts = []
            for b in bins:
                is_wrapped = _is_our_wrapper(b)
                wrapped_count += 1 if is_wrapped else 0
                tag = ok("WRAPPED") if is_wrapped else warn("UNWRAPPED")
                parts.append(f"{b} [{tag}]")
            bin_info = ", ".join(parts)
        else:
            bin_info = note("CLI not detected")
        print(f"  - {name:<8} {profile.display_name:<28} {bin_info}")

    known_paths = {
        os.path.abspath(str(p))
        for bins in discovered.values()
        for p in bins
    }
    custom_wrapped = [
        Path(p) for p in _load_wrapped_registry()
        if os.path.abspath(p) not in known_paths and _is_our_wrapper(Path(p))
    ]
    if custom_wrapped:
        print("\n" + strong("Other custom wrapped paths:"))
        for p in custom_wrapped:
            print(f"  - {p} [{ok('WRAPPED')}]")
    print(
        "\n"
        + note("You can also run any command without wrapping: agent-proxy run <cmd> [args...]")
    )
    if wrapped_count == 0:
        print(note("Nothing is wrapped yet. Run `agent-proxy wrap` to route agent traffic through the proxy."))
    return 0


def cmd_wrap(args: argparse.Namespace) -> int:
    if args.uri:
        uri = args.uri.strip()
        parse_vless_uri(uri)
        save_default_uri(uri)
        print_saved_config()
    else:
        try:
            resolve_upstream_uri(None)
        except ValueError:
            if sys.stdin.isatty():
                prompt_upstream_uri(save=True)
            else:
                raise

    selected_names = _resolve_agent_names(args.agents)
    include_profiles = not args.bin or bool(args.agents)

    raw_targets: List[Path] = [Path(b) for b in (args.bin or [])]
    if include_profiles:
        for name in selected_names:
            raw_targets.extend(_discover_profile_bins(AGENT_PROFILES[name]))

    targets = _dedupe_paths(raw_targets)
    wrapped = [t for t in targets if _wrap_one(t, args.host, args.port)]

    if not wrapped:
        names_str = ", ".join(selected_names) if include_profiles else ", ".join(args.bin or [])
        print(
            fail(
                f"Error: no wrappable CLI detected (targets: {names_str}). "
                "Use `--bin /path/to/cmd` to specify a path, or run `agent-proxy run <cmd>` directly."
            ),
            file=sys.stderr,
        )
        return 1

    print(f"{strong('Proxy')}: {value(f'http://{args.host}:{args.port}')} {note('(auto-starts when not running)')}")

    proc_names: Set[str] = set()
    if include_profiles:
        for name in selected_names:
            proc_names.update(AGENT_PROFILES[name].process_names)
    for t in wrapped:
        proc_names.add(t.name)
        proc_names.add(t.name + ".real")

    running = _running_agent_pids(proc_names)
    if args.restart:
        _restart_agent_processes(proc_names)
    elif running:
        print(warn(f"Note: detected {len(running)} running target process(es) (PID {', '.join(map(str, running))})."))
        print(note("      Running processes keep their old environment; restart them to pick up the proxy:"))
        print(f"        {value('agent-proxy wrap --restart')}")
        print(note("      Or reload the window / reopen the session in your IDE."))

    print(ok(f"Wrapped {len(wrapped)} CLI(s).") + note(" The proxy starts automatically on next use."))
    return 0


def cmd_unwrap(args: argparse.Namespace) -> int:
    unwrap_all = not args.agents and not args.bin
    selected_names = _resolve_agent_names(args.agents) if args.agents else list(AGENT_PROFILES.keys())

    raw_targets: List[Path] = [Path(b) for b in (args.bin or [])]
    if unwrap_all or args.agents:
        for name in selected_names:
            profile = AGENT_PROFILES[name]
            raw_targets.extend(_discover_profile_bins(profile))
            raw_targets.extend(profile.extra_paths)
    if unwrap_all:
        raw_targets.extend(Path(p) for p in _load_wrapped_registry())

    targets = _dedupe_paths(raw_targets)

    restored = 0
    for target in targets:
        if _unwrap_one(target):
            restored += 1

    if restored == 0:
        print(note("Nothing to restore: no wrapped scripts found."))
    else:
        print(ok(f"Restored {restored} CLI(s) to their original binaries."))

    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise ValueError(
            "Missing command to run. Example: agent-proxy run claude (or: agent-proxy run -- npm test)"
        )
    _ensure_proxy_running(args.host, args.port)
    env = os.environ.copy()
    env.update(_proxy_env(args.host, args.port))
    executable = shutil.which(cmd[0], path=env.get("PATH"))
    if not executable:
        raise RuntimeError(f"Command not found: {cmd[0]}")
    os.execvpe(executable, cmd, env)
    return 0


def cmd_env(args: argparse.Namespace) -> int:
    keys = (
        "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
        "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "NODE_USE_ENV_PROXY",
    )
    if args.unset:
        print("unset " + " ".join(keys))
        return 0
    env_map = _proxy_env(args.host, args.port, no_proxy=INTRANET_NO_PROXY if args.intranet_no_proxy else None)
    for k, v in env_map.items():
        print(f"export {k}={shlex.quote(v)}")
    return 0


PATH_MARKER = "# agent-proxy-path"


def _escape_double_quoted(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")


def _detect_shell_and_rc(
    shell_name: str = "auto",
    rc_override: Optional[str] = None,
    home: Optional[Path] = None,
) -> Tuple[str, Path]:
    home_dir = home if home is not None else Path.home()
    shell = (shell_name or "auto").strip().lower()
    if shell == "auto":
        env_shell = Path(os.environ.get("SHELL", "")).name.lower()
        if env_shell in ("zsh", "bash", "fish", "sh"):
            shell = env_shell
        elif sys.platform == "darwin":
            shell = "zsh"
        else:
            shell = "bash"

    if rc_override:
        rc_path = Path(os.path.expanduser(rc_override))
        if shell_name == "auto":
            rc_name = rc_path.name.lower()
            if "fish" in rc_name:
                shell = "fish"
            elif "zsh" in rc_name:
                shell = "zsh"
            elif "bash" in rc_name:
                shell = "bash"
        return shell, rc_path

    if shell == "zsh":
        return "zsh", home_dir / ".zshrc"
    if shell == "fish":
        return "fish", home_dir / ".config" / "fish" / "config.fish"
    if shell == "bash":
        if sys.platform == "darwin":
            bash_profile = home_dir / ".bash_profile"
            bashrc = home_dir / ".bashrc"
            return "bash", bash_profile if (bash_profile.exists() or not bashrc.exists()) else bashrc
        return "bash", home_dir / ".bashrc"
    return "sh", home_dir / ".profile"


def _path_export_line(bin_dir: Path, shell: str) -> str:
    escaped = _escape_double_quoted(str(bin_dir))
    if shell == "fish":
        return f'fish_add_path "{escaped}"  {PATH_MARKER}'
    return f'export PATH="{escaped}:$PATH"  {PATH_MARKER}'


def _install_to_path(bin_dir: Path, rc_path: Path, shell: str) -> str:
    """Add bin_dir to PATH in rc_path. Returns status: 'added', 'updated', or 'exists'."""
    target_dir = Path(os.path.abspath(str(bin_dir)))
    export_line = _path_export_line(target_dir, shell)

    existing_lines: List[str] = []
    if rc_path.exists():
        existing_lines = rc_path.read_text(encoding="utf-8").splitlines()

    # 1. Check for existing managed marker line
    for idx, line in enumerate(existing_lines):
        if PATH_MARKER in line:
            if line.strip() == export_line.strip():
                return "exists"
            existing_lines[idx] = export_line
            rc_path.write_text("\n".join(existing_lines) + "\n", encoding="utf-8")
            return "updated"

    # 2. Avoid duplicating a manual PATH entry for the exact same directory
    dir_str = str(target_dir)
    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if dir_str in stripped and ("PATH" in stripped or "fish_add_path" in stripped):
            return "exists"

    # 3. Append new managed line
    rc_path.parent.mkdir(parents=True, exist_ok=True)
    if existing_lines and existing_lines[-1] != "":
        existing_lines.append("")
    existing_lines.append(export_line)
    rc_path.write_text("\n".join(existing_lines) + "\n", encoding="utf-8")
    return "added"


def _uninstall_from_path(rc_path: Path) -> bool:
    if not _path_exists_safe(rc_path):
        return False
    raw = rc_path.read_text(encoding="utf-8")
    lines = raw.splitlines()
    new_lines = [line for line in lines if PATH_MARKER not in line]
    if len(new_lines) == len(lines):
        return False
    # Clean up trailing blank line left behind by our appended block
    while len(new_lines) >= 2 and new_lines[-1] == "" and new_lines[-2] == "":
        new_lines.pop()
    content = ("\n".join(new_lines) + "\n") if new_lines else ""
    rc_path.write_text(content, encoding="utf-8")
    return True


def _dir_on_path(directory: Path) -> bool:
    target = os.path.abspath(str(directory))
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if entry and os.path.abspath(os.path.expanduser(entry)) == target:
            return True
    return False


def cmd_install(args: argparse.Namespace) -> int:
    if args.remove:
        return cmd_uninstall(args)
    bin_dir = Path(os.path.expanduser(args.dir)).resolve() if args.dir else Path(__file__).resolve().parent
    if not bin_dir.is_dir():
        raise ValueError(f"Directory does not exist: {bin_dir}")
    shell, rc_path = _detect_shell_and_rc(args.shell, args.rc)
    status = _install_to_path(bin_dir, rc_path, shell)
    if status == "exists":
        print(f"{note('PATH already includes')} {value(str(bin_dir))} {note(f'(config: {rc_path}); nothing to add.')}")
    elif status == "updated":
        print(f"{ok('Updated agent-proxy PATH entry')} in {value(str(rc_path))} to: {value(str(bin_dir))}")
    else:
        print(f"{ok('Added')} {value(str(bin_dir))} {ok('to PATH')} (updated: {value(str(rc_path))})")
    if _dir_on_path(bin_dir):
        print(ok("agent-proxy is ready to use."))
    else:
        print(note("New terminals pick this up automatically."))
        print(note("To use it in this terminal now: ") + value(f"source {shlex.quote(str(rc_path))}"))
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    home = Path.home()
    candidates: List[Path] = []
    if getattr(args, "rc", None):
        candidates.append(Path(os.path.expanduser(args.rc)))
    else:
        _, detected_rc = _detect_shell_and_rc(getattr(args, "shell", "auto"), None, home=home)
        for p in (
            detected_rc,
            home / ".zshrc",
            home / ".bashrc",
            home / ".bash_profile",
            home / ".profile",
            home / ".config" / "fish" / "config.fish",
        ):
            if p not in candidates:
                candidates.append(p)

    removed_from: List[Path] = []
    for rc_path in candidates:
        if _uninstall_from_path(rc_path):
            removed_from.append(rc_path)

    if removed_from:
        for rc_path in removed_from:
            print(ok(f"Removed agent-proxy PATH entry from {rc_path}."))
        print(note("Open a new terminal for the change to take effect there."))
    else:
        print(note("Nothing to remove: no agent-proxy PATH entry found in shell config files."))
    return 0


DEFAULT_REPO_URL = "https://github.com/vFrida/agent-proxy.git"
DEFAULT_UPDATE_REF = "main"


def _run_git(
    repo_dir: Path,
    *git_args: str,
    check: bool = True,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess:
    cmd = ["git", "-C", str(repo_dir), *git_args]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"git {' '.join(git_args)} timed out after {timeout:.0f}s") from exc
    if check and res.returncode != 0:
        detail = (res.stderr or res.stdout).strip() or f"exit code {res.returncode}"
        raise RuntimeError(f"git {' '.join(git_args)} failed: {detail}")
    return res


def _get_git_version(repo_dir: Optional[Path] = None) -> Tuple[Optional[int], Optional[str], bool]:
    target_dir = repo_dir if repo_dir is not None else Path(__file__).resolve().parent
    if not shutil.which("git") or not _path_exists_safe(target_dir / ".git"):
        return None, None, False
    count_res = _run_git(target_dir, "rev-list", "--count", "HEAD", check=False)
    if count_res.returncode != 0:
        return None, None, False
    try:
        commit_count = int(count_res.stdout.strip())
    except ValueError:
        return None, None, False
    sha_res = _run_git(target_dir, "rev-parse", "--short", "HEAD", check=False)
    short_sha = sha_res.stdout.strip() if sha_res.returncode == 0 else None
    is_shallow = _path_exists_safe(target_dir / ".git" / "shallow")
    return commit_count, short_sha, is_shallow


def _format_version(repo_dir: Optional[Path] = None, short: bool = False) -> str:
    count, sha, is_shallow = _get_git_version(repo_dir)
    if count is None:
        return "0" if short else "agent-proxy (unknown version: not a git checkout)"
    if short:
        return str(count)
    parts = [f"agent-proxy v{count}"]
    if sha:
        parts.append(f"({sha})")
    if is_shallow:
        parts.append("[shallow]")
    return " ".join(parts)


def cmd_version(args: argparse.Namespace) -> int:
    repo_dir = Path(os.path.expanduser(args.dir)).resolve() if getattr(args, "dir", None) else Path(__file__).resolve().parent
    print(_format_version(repo_dir, short=getattr(args, "short", False)))
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    if not shutil.which("git"):
        raise RuntimeError("git is required to update agent-proxy.")

    repo_dir = Path(os.path.expanduser(args.dir)).resolve() if args.dir else Path(__file__).resolve().parent
    if not repo_dir.is_dir():
        raise ValueError(f"Directory does not exist: {repo_dir}")

    explicit_url = (args.repo_url or os.environ.get("AGENT_PROXY_REPO_URL") or "").strip()
    explicit_ref = (args.ref or os.environ.get("AGENT_PROXY_REF") or "").strip()
    is_git_repo = _path_exists_safe(repo_dir / ".git")

    old_count, old_sha, _ = _get_git_version(repo_dir)

    if is_git_repo:
        # Determine target ref (explicit -> current branch -> default main)
        ref = explicit_ref
        if not ref:
            branch_res = _run_git(repo_dir, "symbolic-ref", "--short", "HEAD", check=False)
            ref = branch_res.stdout.strip() if branch_res.returncode == 0 and branch_res.stdout.strip() else DEFAULT_UPDATE_REF

        # Determine remote URL
        if explicit_url:
            repo_url = explicit_url
            set_res = _run_git(repo_dir, "remote", "set-url", "origin", repo_url, check=False)
            if set_res.returncode != 0:
                _run_git(repo_dir, "remote", "add", "origin", repo_url)
        else:
            url_res = _run_git(repo_dir, "remote", "get-url", "origin", check=False)
            if url_res.returncode == 0 and url_res.stdout.strip():
                repo_url = url_res.stdout.strip()
            else:
                repo_url = DEFAULT_REPO_URL
                _run_git(repo_dir, "remote", "add", "origin", repo_url)

        # Refuse to clobber uncommitted tracked changes unless --force
        status_res = _run_git(repo_dir, "status", "--porcelain", "--untracked-files=no")
        if status_res.stdout.strip() and not args.force:
            raise RuntimeError(
                f"Uncommitted changes detected in {repo_dir}. "
                "Commit or stash them first, or re-run with `agent-proxy update --force`."
            )

        print(f"{note('Fetching latest changes from')} {value(repo_url)} {note(f'({ref})...')}")
        if _path_exists_safe(repo_dir / ".git" / "shallow"):
            unshallow_res = _run_git(
                repo_dir, "fetch", "--unshallow", "origin", ref, check=False, timeout=300.0
            )
            if unshallow_res.returncode != 0:
                _run_git(repo_dir, "fetch", "origin", ref, timeout=300.0)
        else:
            _run_git(repo_dir, "fetch", "origin", ref, timeout=300.0)

        _run_git(repo_dir, "checkout", "-f", "-B", ref, "FETCH_HEAD")
    else:
        repo_url = explicit_url or DEFAULT_REPO_URL
        ref = explicit_ref or DEFAULT_UPDATE_REF
        print(f"{note('Initializing git repository in')} {value(str(repo_dir))} {note(f'from {repo_url} ({ref})...')}")
        _run_git(repo_dir, "init", "-q")
        _run_git(repo_dir, "remote", "add", "origin", repo_url)
        _run_git(repo_dir, "fetch", "origin", ref, timeout=300.0)
        _run_git(repo_dir, "checkout", "-f", "-B", ref, "FETCH_HEAD")

    for exe_name in ("agent-proxy", "agent_proxy.py"):
        exe_path = repo_dir / exe_name
        if exe_path.is_file():
            os.chmod(exe_path, 0o755)

    new_count, new_sha, _ = _get_git_version(repo_dir)
    if old_sha and new_sha and old_sha == new_sha:
        print(warn(f"Already up to date: {_format_version(repo_dir)}"))
        return 0

    if old_count is not None and new_count is not None:
        old_label = f"v{old_count} ({old_sha})" if old_sha else f"v{old_count}"
        new_label = f"v{new_count} ({new_sha})" if new_sha else f"v{new_count}"
        print(f"{ok('Updated agent-proxy:')} {old_label} -> {value(new_label)}")
    else:
        print(f"{ok('Updated agent-proxy to')} {value(_format_version(repo_dir))}")

    running_state = read_running_state()
    if running_state:
        if args.restart:
            host = str(running_state.get("listen_host") or DEFAULT_LISTEN_HOST)
            port = _as_int(running_state.get("listen_port"), DEFAULT_LISTEN_PORT)
            stop_daemon()
            uri = resolve_upstream_uri(None)
            new_state = start_daemon(uri, host, port, insecure=False, verbose=False)
            print(ok(f"Restarted proxy daemon (PID {new_state['pid']}) on {host}:{port}."))
        else:
            print(warn("Note: proxy daemon is running; run `agent-proxy stop && agent-proxy start -d` (or `agent-proxy update --restart`) to reload."))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-proxy",
        description="Zero-dependency local proxy & multi-agent CLI wrapper (Antigravity / Claude / Codex / Cursor).",
        epilog=(
            "Examples:\n"
            "  agent-proxy start -d                 Start the background proxy\n"
            "  agent-proxy wrap                     Route all detected agents through the proxy\n"
            "  agent-proxy run codex -- --help      Run one command with proxy env vars\n"
            "  agent-proxy env                      Print shell exports for this terminal\n"
            "  agent-proxy status                   Show daemon status and endpoints"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-V", "--version", action="version", version=_format_version())
    sub = p.add_subparsers(dest="command", required=True)

    # start
    p_start = sub.add_parser("start", help="Start the local HTTP/HTTPS/SOCKS5 proxy")
    p_start.add_argument("--uri", help="Upstream VLESS URI (defaults to saved config, or prompts interactively)")
    p_start.add_argument("--host", default=DEFAULT_LISTEN_HOST, help=f"Listen host (default: {DEFAULT_LISTEN_HOST})")
    p_start.add_argument("--port", type=int, default=DEFAULT_LISTEN_PORT, help=f"Listen port (default: {DEFAULT_LISTEN_PORT})")
    p_start.add_argument("-d", "--daemon", action="store_true", help="Run in background as a daemon")
    p_start.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification for upstream server")
    p_start.add_argument("--save", action="store_true", help="Save --uri as the default upstream node")
    p_start.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    p_start.set_defaults(func=cmd_start)

    # stop
    p_stop = sub.add_parser("stop", help="Stop the background proxy daemon")
    p_stop.set_defaults(func=cmd_stop)

    # status
    p_status = sub.add_parser("status", help="Show background proxy status")
    p_status.set_defaults(func=cmd_status)

    # list / agents
    p_list = sub.add_parser("list", aliases=["agents"], help="List supported coding agents and their wrap status")
    p_list.set_defaults(func=cmd_list)

    # wrap
    p_wrap = sub.add_parser(
        "wrap",
        help="Wrap CLI tools (agy / claude / codex / cursor) to auto-use the proxy",
        description="Replace agent launchers with wrappers that start the local proxy and inject proxy env vars.",
    )
    p_wrap.add_argument("agents", nargs="*", help="Target agents: agy, claude, codex, cursor, or all (default: all detected)")
    p_wrap.add_argument("--uri", help="Upstream VLESS URI to save before wrapping (prompts interactively if not yet configured)")
    p_wrap.add_argument("--host", default=DEFAULT_LISTEN_HOST, help=f"Proxy host (default: {DEFAULT_LISTEN_HOST})")
    p_wrap.add_argument("--port", type=int, default=DEFAULT_LISTEN_PORT, help=f"Proxy port (default: {DEFAULT_LISTEN_PORT})")
    p_wrap.add_argument("--bin", action="append", metavar="PATH", help="Extra CLI path to wrap (repeatable)")
    p_wrap.add_argument("--restart", action="store_true", help="Terminate running target processes so they pick up the new proxy env")
    p_wrap.set_defaults(func=cmd_wrap)

    # unwrap
    p_unwrap = sub.add_parser("unwrap", help="Restore wrapped CLI tools")
    p_unwrap.add_argument("agents", nargs="*", help="Target agents to unwrap (default: all wrapped)")
    p_unwrap.add_argument("--bin", action="append", metavar="PATH", help="Extra CLI path to restore (repeatable)")
    p_unwrap.set_defaults(func=cmd_unwrap)

    # run
    p_run = sub.add_parser("run", help="Run any command with local proxy env (auto-starts daemon)")
    p_run.add_argument("--host", default=DEFAULT_LISTEN_HOST, help=f"Proxy host (default: {DEFAULT_LISTEN_HOST})")
    p_run.add_argument("--port", type=int, default=DEFAULT_LISTEN_PORT, help=f"Proxy port (default: {DEFAULT_LISTEN_PORT})")
    p_run.add_argument("cmd", nargs=argparse.REMAINDER, help="Command and arguments to execute")
    p_run.set_defaults(func=cmd_run)

    # env
    p_env = sub.add_parser("env", help="Print shell export/unset statements for current terminal")
    p_env.add_argument("--host", default=DEFAULT_LISTEN_HOST, help=f"Proxy host (default: {DEFAULT_LISTEN_HOST})")
    p_env.add_argument("--port", type=int, default=DEFAULT_LISTEN_PORT, help=f"Proxy port (default: {DEFAULT_LISTEN_PORT})")
    p_env.add_argument("--intranet-no-proxy", action="store_true", help="Include intranet/private CIDRs in NO_PROXY")
    p_env.add_argument("--unset", action="store_true", help="Print unset statements instead of export")
    p_env.set_defaults(func=cmd_env)

    # install (add agent-proxy directory to PATH)
    p_install = sub.add_parser(
        "install",
        aliases=["add-path"],
        help="Add the agent-proxy directory to your shell PATH",
    )
    p_install.add_argument(
        "--shell",
        choices=("auto", "zsh", "bash", "fish", "sh"),
        default="auto",
        help="Target shell (default: auto-detect from $SHELL)",
    )
    p_install.add_argument("--rc", metavar="PATH", help="Explicit shell rc file path to update")
    p_install.add_argument("--dir", metavar="PATH", help="Directory to add to PATH (default: agent-proxy directory)")
    p_install.add_argument("--remove", action="store_true", help="Remove agent-proxy PATH entry instead of adding")
    p_install.set_defaults(func=cmd_install)

    # uninstall (remove agent-proxy directory from PATH)
    p_uninstall = sub.add_parser(
        "uninstall",
        aliases=["remove-path"],
        help="Remove the agent-proxy PATH entry added by `install`",
    )
    p_uninstall.add_argument(
        "--shell",
        choices=("auto", "zsh", "bash", "fish", "sh"),
        default="auto",
        help="Target shell (default: auto-detect from $SHELL)",
    )
    p_uninstall.add_argument("--rc", metavar="PATH", help="Explicit shell rc file path to clean")
    p_uninstall.set_defaults(func=cmd_uninstall)

    # version
    p_version = sub.add_parser("version", help="Show version (total git commit count)")
    p_version.add_argument("--short", action="store_true", help="Print only the numeric commit count")
    p_version.add_argument("--dir", metavar="PATH", help="Repository directory (default: agent-proxy directory)")
    p_version.set_defaults(func=cmd_version)

    # update
    p_update = sub.add_parser("update", aliases=["upgrade"], help="Pull the latest version of agent-proxy from GitHub")
    p_update.add_argument("--ref", help="Git branch, tag, or commit to update to (default: current branch or main)")
    p_update.add_argument("--repo-url", help=f"Git repository URL (default: current origin or {DEFAULT_REPO_URL})")
    p_update.add_argument("--dir", metavar="PATH", help="Repository directory to update (default: agent-proxy directory)")
    p_update.add_argument("--force", action="store_true", help="Overwrite uncommitted local changes to tracked files")
    p_update.add_argument("--restart", action="store_true", help="Restart the background proxy daemon if running")
    p_update.set_defaults(func=cmd_update)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ValueError as exc:
        print(fail(f"Error: {exc}"), file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(fail(f"Error: {exc}"), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(note("Interrupted."), file=sys.stderr)
        return 130
    except OSError as exc:
        print(fail(f"System error: {exc}"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
