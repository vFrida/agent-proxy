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
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

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

    host = parsed.hostname
    if not host:
        raise ValueError("VLESS URI is missing server hostname")
    port = parsed.port or 443

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

    def handler(ev_loop: asyncio.AbstractEventLoop, context: Dict[str, object]) -> None:
        msg = str(context.get("message", ""))
        exc = context.get("exception")
        if "Fatal error on SSL transport" in msg and isinstance(exc, (OSError, RuntimeError)):
            return
        default_handler(context)

    loop.set_exception_handler(handler)


# ---------------------------------------------------------------------------
# Local Mixed HTTP / HTTPS CONNECT / SOCKS5 Proxy Server
# ---------------------------------------------------------------------------


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
        self._active_conns = 0
        self._client_tasks: Set[asyncio.Task] = set()

    @property
    def bound_port(self) -> int:
        if self._server and self._server.sockets:
            return int(self._server.sockets[0].getsockname()[1])
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

        connect_kwargs: Dict[str, object] = {}
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
        except (asyncio.CancelledError, ConnectionError, BrokenPipeError, OSError):
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
        except (asyncio.CancelledError, asyncio.IncompleteReadError, ConnectionError, BrokenPipeError, OSError):
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
        self._active_conns += 1
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
            self._active_conns -= 1
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
        if 0x00 not in methods:
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
            client_writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await client_writer.drain()
            return None

        if atyp == 0x01:  # IPv4
            target_host = socket.inet_ntop(socket.AF_INET, await client_reader.readexactly(4))
        elif atyp == 0x03:  # Domain
            dlen = (await client_reader.readexactly(1))[0]
            target_host = (await client_reader.readexactly(dlen)).decode("utf-8", errors="replace")
        elif atyp == 0x04:  # IPv6
            target_host = socket.inet_ntop(socket.AF_INET6, await client_reader.readexactly(16))
        else:
            client_writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await client_writer.drain()
            return None

        target_port = struct.unpack("!H", await client_reader.readexactly(2))[0]
        logger.debug("SOCKS5 CONNECT %s:%d", target_host, target_port)

        try:
            remote_reader, remote_writer, is_vless = await self._open_upstream(target_host, target_port)
        except Exception as exc:
            logger.warning("SOCKS5 upstream failed for %s:%d: %s", target_host, target_port, exc)
            client_writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            await client_writer.drain()
            return None

        # Reply SUCCEEDED immediately (VLESS response header arrives lazily after client sends payload)
        client_writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
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
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return None

        raw_header = first_byte + rest_head
        header_text = raw_header.decode("latin-1")
        lines = header_text.split("\r\n")
        if not lines:
            return None

        parts = lines[0].split(" ")
        if len(parts) < 3:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await client_writer.drain()
            return None

        method, target, http_version = parts[0].upper(), parts[1], parts[2]
        header_lines = [line for line in lines[1:] if line]

        if method == "CONNECT":
            target_host, target_port = _parse_host_port(target, default_port=443)
            logger.debug("HTTP CONNECT %s:%d", target_host, target_port)
            try:
                remote_reader, remote_writer, is_vless = await self._open_upstream(target_host, target_port)
            except Exception as exc:
                logger.warning("HTTP CONNECT upstream failed for %s:%d: %s", target_host, target_port, exc)
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                await client_writer.drain()
                return None

            client_writer.write(f"{http_version} 200 Connection Established\r\n\r\n".encode("latin-1"))
            await client_writer.drain()

            await self._relay(client_reader, client_writer, remote_reader, remote_writer, is_vless)
            return remote_writer

        # Plain HTTP request forwarding
        if target.startswith(("http://", "https://")):
            parsed_url = urllib.parse.urlsplit(target)
            target_host = parsed_url.hostname or ""
            target_port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
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
                client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await client_writer.drain()
                return None
            target_host, target_port = _parse_host_port(host_header, default_port=80)
            path = target

        if not target_host:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await client_writer.drain()
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
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await client_writer.drain()
            return None

        await self._relay(client_reader, client_writer, remote_reader, remote_writer, is_vless)
        return remote_writer


def _parse_host_port(authority: str, default_port: int) -> Tuple[str, int]:
    authority = authority.strip()
    if authority.startswith("["):
        end_bracket = authority.find("]")
        if end_bracket == -1:
            raise ValueError(f"Malformed IPv6 authority: {authority}")
        host = authority[1:end_bracket]
        rest = authority[end_bracket + 1 :]
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, default_port
    if ":" in authority:
        host, port_str = authority.rsplit(":", 1)
        return host, int(port_str)
    return authority, default_port


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
    print("No upstream proxy node configured. Enter a VLESS URI (format: vless://<uuid>@<host>:<port>?...)")
    while True:
        try:
            entered = input("Enter proxy node URI: ").strip()
        except (EOFError, KeyboardInterrupt) as exc:
            raise ValueError("Cancelled entering proxy node URI.") from exc
        if not entered:
            print("Proxy node URI cannot be empty; please try again.", file=sys.stderr)
            continue
        try:
            parse_vless_uri(entered, force_insecure=force_insecure)
        except ValueError as exc:
            print(f"Invalid node URI: {exc}. Please try again.", file=sys.stderr)
            continue
        if save:
            save_default_uri(entered)
            print(f"Saved node config to: {CONFIG_FILE}")
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


def save_default_uri(uri: str) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps({"upstream_uri": uri}, indent=2) + "\n", encoding="utf-8")


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


def read_running_state() -> Optional[Dict[str, object]]:
    if not PID_FILE.exists():
        return None
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except Exception:
        return None
    if not _pid_alive(pid):
        return None
    state: Dict[str, object] = {"pid": pid}
    if STATE_FILE.exists():
        try:
            state.update(json.loads(STATE_FILE.read_text(encoding="utf-8")))
        except Exception:
            pass
    return state


def write_running_state(pid: int, host: str, port: int, node: VlessNode) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(f"{pid}\n", encoding="utf-8")
    STATE_FILE.write_text(
        json.dumps(
            {
                "pid": pid,
                "listen_host": host,
                "listen_port": port,
                "node": node.display_label(),
                "started_at": int(time.time()),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def clear_running_state() -> None:
    for p in (PID_FILE, STATE_FILE):
        try:
            p.unlink()
        except FileNotFoundError:
            pass


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def start_daemon(uri: str, host: str, port: int, insecure: bool, verbose: bool) -> Dict[str, object]:
    existing = read_running_state()
    if existing:
        if (
            existing.get("listen_host") == host
            and int(existing.get("listen_port", -1)) == port
            and _wait_for_port(host, port, timeout=0.5)
        ):
            return existing
        # Stale or different port; stop previous daemon first
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
        tail = ""
        if LOG_FILE.exists():
            tail = LOG_FILE.read_text(encoding="utf-8", errors="replace")[-1000:]
        raise RuntimeError(f"Proxy daemon failed to start on {host}:{port}.\nLog tail:\n{tail}")

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
    clear_running_state()
    return True


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
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
        print(f"Proxy started in background (PID {state['pid']})")
        print(f"  HTTP/HTTPS : http://{args.host}:{args.port}")
        print(f"  SOCKS5     : socks5h://{args.host}:{args.port}")
        print(f"  Upstream   : {node.display_label()}")
        print(f"  Log file   : {LOG_FILE}")
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
        print("Proxy daemon stopped.")
    else:
        print("Proxy daemon is not running.")
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    state = read_running_state()
    if not state:
        print("Status: STOPPED")
        try:
            configured = resolve_upstream_uri(None)
            print(f"Default upstream: {parse_vless_uri(configured).display_label()}")
        except ValueError:
            print("Default upstream: (not configured; run `agent-proxy start -d` to enter a node URI)")
        return 1
    host = state.get("listen_host", DEFAULT_LISTEN_HOST)
    port = state.get("listen_port", DEFAULT_LISTEN_PORT)
    reachable = _wait_for_port(str(host), int(port), timeout=0.5)
    print(f"Status     : {'RUNNING' if reachable else 'STARTING/UNREACHABLE'} (PID {state['pid']})")
    print(f"HTTP/HTTPS : http://{host}:{port}")
    print(f"SOCKS5     : socks5h://{host}:{port}")
    print(f"Upstream   : {state.get('node', 'unknown')}")
    print(f"Log file   : {LOG_FILE}")
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
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    WRAPPED_FILE.write_text(json.dumps({"wrapped": unique}, indent=2) + "\n", encoding="utf-8")


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
    app = Path(__file__).resolve()
    py = sys.executable or "/usr/bin/python3"
    return f'''#!/bin/sh
{WRAPPER_MARKER}
# Generated by `agent-proxy wrap`: injects local proxy env vars before launching `{bin_name}`.
# Uninstall: `agent-proxy unwrap` (restores {bin_name}.real back to {bin_name}).
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_DIR="$SELF_DIR"
BIN_NAME="{bin_name}"
PY="{py}"
APP="{app}"
HOST="{host}"
PORT="{port}"
PROXY="http://$HOST:$PORT"

# 1) Locate the real entry point: original file/symlink renamed to ${{BIN_NAME}}.real during wrap
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
  echo "agent-proxy: could not find real $BIN_NAME (expected $BIN_DIR/${{BIN_NAME}}.real)" >&2
  exit 127
fi

# 2) Start the local proxy daemon if it is not listening yet (wait up to 5s)
if ! nc -z -w 1 "$HOST" "$PORT" >/dev/null 2>&1; then
  "$PY" "$APP" start -d --host "$HOST" --port "$PORT" >/dev/null 2>&1 &
  i=0
  while [ $i -lt 50 ]; do
    nc -z -w 1 "$HOST" "$PORT" >/dev/null 2>&1 && break
    i=$((i + 1))
    sleep 0.1
  done
fi

# 3) Inject proxy env vars (compatible with Go/Node/Python/Rust CLIs)
export HTTP_PROXY="$PROXY"  HTTPS_PROXY="$PROXY"
export http_proxy="$PROXY"  https_proxy="$PROXY"
export ALL_PROXY="socks5h://$HOST:$PORT"  all_proxy="socks5h://$HOST:$PORT"
export NO_PROXY="${{NO_PROXY:-{DEFAULT_NO_PROXY}}}"
export no_proxy="${{no_proxy:-{DEFAULT_NO_PROXY}}}"
export NODE_USE_ENV_PROXY=1

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
        print(f"  Preserved original binary: {target} -> {real.name}")
    target.write_text(_wrapper_script(target.name, host, port), encoding="utf-8")
    os.chmod(target, 0o755)
    _record_wrapped_path(target)
    print(f"  Wrapped: {target}")
    return True


def _unwrap_one(target: Path) -> bool:
    real = target.with_name(target.name + ".real")
    if _is_our_wrapper(target) and (real.is_symlink() or real.exists()):
        os.replace(real, target)
        _forget_wrapped_path(target)
        print(f"  Restored: {target}")
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
        print("  No running target processes need to be restarted.")
        return 0
    print(f"  Restarting processes: {pids}")
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            print(f"  Skipped process {pid} (permission denied)")
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
    print("  Stopped old processes; the next invocation or IDE session will automatically use the proxy.")
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
    print("Supported Coding Agents:")
    for name, profile in AGENT_PROFILES.items():
        bins = _discover_profile_bins(profile)
        if bins:
            parts = []
            for b in bins:
                tag = "WRAPPED" if _is_our_wrapper(b) else "UNWRAPPED"
                parts.append(f"{b} [{tag}]")
            bin_info = ", ".join(parts)
        else:
            bin_info = "CLI not detected"
        print(f"  - {name:<8} {profile.display_name:<28} {bin_info}")

    known_paths = {
        os.path.abspath(str(p))
        for profile in AGENT_PROFILES.values()
        for p in _discover_profile_bins(profile)
    }
    custom_wrapped = [
        Path(p) for p in _load_wrapped_registry()
        if os.path.abspath(p) not in known_paths and _is_our_wrapper(Path(p))
    ]
    if custom_wrapped:
        print("\nOther custom wrapped paths:")
        for p in custom_wrapped:
            print(f"  - {p} [WRAPPED]")
    print("\nYou can also run any command without wrapping: agent-proxy run <cmd> [args...]")
    return 0


def cmd_wrap(args: argparse.Namespace) -> int:
    if args.uri:
        uri = args.uri.strip()
        parse_vless_uri(uri)
        save_default_uri(uri)
        print(f"Saved node config to: {CONFIG_FILE}")
    else:
        try:
            resolve_upstream_uri(None)
        except ValueError:
            if sys.stdin.isatty():
                prompt_upstream_uri(save=True)
            else:
                raise

    selected_names = _resolve_agent_names(args.agents)
    targets: List[Path] = []
    seen: Set[str] = set()

    def add_target(p: Path) -> None:
        norm = os.path.abspath(str(p))
        if norm not in seen:
            seen.add(norm)
            targets.append(Path(norm))

    for b in (args.bin or []):
        add_target(Path(os.path.expanduser(b)))

    include_profiles = not args.bin or bool(args.agents)
    if include_profiles:
        for name in selected_names:
            for p in _discover_profile_bins(AGENT_PROFILES[name]):
                add_target(p)

    wrapped = [t for t in targets if _wrap_one(t, args.host, args.port)]

    if not wrapped:
        names_str = ", ".join(selected_names) if include_profiles else ", ".join(args.bin or [])
        print(
            f"Error: no wrappable CLI detected (targets: {names_str}). "
            "Use `--bin /path/to/cmd` to specify a path, or run `agent-proxy run <cmd>` directly.",
            file=sys.stderr,
        )
        return 1

    print(f"Proxy: http://{args.host}:{args.port} (auto-starts when not running)")

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
        print(f"Note: detected {len(running)} running target process(es) (PID {', '.join(map(str, running))}).")
        print("      Existing processes have a fixed environment and must be restarted to take effect:")
        print("        agent-proxy wrap --restart")
        print("      Or run Reload Window / reopen the session in your IDE.")

    return 0


def cmd_unwrap(args: argparse.Namespace) -> int:
    unwrap_all = not args.agents and not args.bin
    selected_names = _resolve_agent_names(args.agents) if args.agents else list(AGENT_PROFILES.keys())
    targets: List[Path] = []
    seen: Set[str] = set()

    def add_target(p: Path) -> None:
        norm = os.path.abspath(str(p))
        if norm not in seen:
            seen.add(norm)
            targets.append(Path(norm))

    for b in (args.bin or []):
        add_target(Path(os.path.expanduser(b)))

    if unwrap_all or args.agents:
        for name in selected_names:
            profile = AGENT_PROFILES[name]
            for p in _discover_profile_bins(profile):
                add_target(p)
            for p in profile.extra_paths:
                add_target(p)

    if unwrap_all:
        for p in _load_wrapped_registry():
            add_target(Path(p))

    restored = 0
    for target in targets:
        if _unwrap_one(target):
            restored += 1

    if restored == 0:
        print("No wrapped scripts found to restore.")

    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise ValueError("Missing command to run. Example: agent-proxy run claude")
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


def cmd_install(args: argparse.Namespace) -> int:
    if args.remove:
        return cmd_uninstall(args)
    bin_dir = Path(os.path.expanduser(args.dir)).resolve() if args.dir else Path(__file__).resolve().parent
    if not bin_dir.is_dir():
        raise ValueError(f"Directory does not exist: {bin_dir}")
    shell, rc_path = _detect_shell_and_rc(args.shell, args.rc)
    status = _install_to_path(bin_dir, rc_path, shell)
    if status == "exists":
        print(f"PATH already includes {bin_dir} (config: {rc_path}); nothing to add.")
    elif status == "updated":
        print(f"Updated agent-proxy PATH entry in {rc_path} to: {bin_dir}")
    else:
        print(f"Added {bin_dir} to PATH (updated: {rc_path})")
    print("Run the following command to apply in the current terminal (new terminals apply automatically):")
    print(f"  source {shlex.quote(str(rc_path))}")
    print("Then you can run `agent-proxy status` from any directory.")
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
            print(f"Removed agent-proxy PATH entry from {rc_path}.")
        print("Restart your terminal or re-source the shell config file to apply.")
    else:
        print("No agent-proxy PATH entry found in shell config files.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-proxy",
        description="Zero-dependency local proxy & multi-agent CLI wrapper (Antigravity / Claude / Codex / Cursor).",
    )
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
    p_wrap = sub.add_parser("wrap", help="Wrap CLI tools (agy / claude / codex / cursor) to auto-use proxy")
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

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
