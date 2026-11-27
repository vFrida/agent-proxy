#!/usr/bin/env python3
"""Unit & loopback integration tests for agent_proxy.py (no external network required)."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import struct
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent_proxy as mod

SAMPLE_VLESS_URI = (
    "vless://00000000-0000-4000-8000-000000000001@proxy.example.com:443"
    "?encryption=none&security=tls&type=tcp&headerType=none#DEMO"
)


async def _mock_target_echo_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        data = await reader.read(4096)
        if data.startswith(b"GET "):
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO")
            await writer.drain()
        elif data:
            writer.write(b"ECHO:" + data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def _mock_upstream_server(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    expected_uuid: uuid.UUID,
    recorded_targets: list,
) -> None:
    remote_writer = None
    try:
        ver = (await reader.readexactly(1))[0]
        assert ver == 0, f"unexpected version {ver}"
        uid = uuid.UUID(bytes=await reader.readexactly(16))
        assert uid == expected_uuid, f"unexpected uuid {uid}"
        addons_len = (await reader.readexactly(1))[0]
        if addons_len:
            await reader.readexactly(addons_len)
        cmd = (await reader.readexactly(1))[0]
        assert cmd == 0x01
        port = struct.unpack("!H", await reader.readexactly(2))[0]
        atyp = (await reader.readexactly(1))[0]
        if atyp == 0x01:
            host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
        elif atyp == 0x02:
            dlen = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(dlen)).decode("utf-8")
        elif atyp == 0x03:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            raise ValueError(f"unknown atyp {atyp}")

        recorded_targets.append((host, port))

        # Wait for the first payload byte BEFORE writing response header,
        # verifying the proxy does not deadlock on delayed upstream headers.
        first_payload = await reader.read(4096)
        r_reader, remote_writer = await asyncio.open_connection("127.0.0.1", port)
        if first_payload:
            remote_writer.write(first_payload)
            await remote_writer.drain()

        resp = await r_reader.read(4096)
        writer.write(b"\x00\x00" + resp)
        await writer.drain()
    finally:
        if remote_writer is not None:
            remote_writer.close()
            await remote_writer.wait_closed()
        writer.close()
        await writer.wait_closed()


class TestAgentProxy(unittest.TestCase):
    def test_parse_vless_uri(self) -> None:
        node = mod.parse_vless_uri(SAMPLE_VLESS_URI)
        self.assertEqual(str(node.user_uuid), "00000000-0000-4000-8000-000000000001")
        self.assertEqual(node.host, "proxy.example.com")
        self.assertEqual(node.port, 443)
        self.assertEqual(node.encryption, "none")
        self.assertEqual(node.security, "tls")
        self.assertEqual(node.transport, "tcp")
        self.assertEqual(node.header_type, "none")
        self.assertEqual(node.sni, "proxy.example.com")
        self.assertEqual(node.remark, "DEMO")

    def test_resolve_upstream_uri_requires_user_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            orig_state = mod.STATE_DIR
            orig_legacy = mod.LEGACY_STATE_DIR
            orig_cfg = mod.CONFIG_FILE
            mod.STATE_DIR = tmp_path / ".agent-proxy"
            mod.LEGACY_STATE_DIR = tmp_path / ".legacy"
            mod.CONFIG_FILE = mod.STATE_DIR / "config.json"
            try:
                with mock.patch.dict(os.environ, {}, clear=True):
                    # Non-interactive raises ValueError
                    with mock.patch.object(mod.sys.stdin, "isatty", return_value=False):
                        with self.assertRaises(ValueError):
                            mod.resolve_upstream_uri(None, prompt_if_missing=True)

                    # Interactive retries invalid input, accepts valid URI, and persists it
                    with mock.patch.object(mod.sys.stdin, "isatty", return_value=True), \
                            mock.patch("builtins.input", side_effect=["", "http://invalid", SAMPLE_VLESS_URI]):
                        resolved = mod.resolve_upstream_uri(None, prompt_if_missing=True, save_prompted=True)
                    self.assertEqual(resolved, SAMPLE_VLESS_URI)
                    self.assertEqual(mod.load_saved_uri(), SAMPLE_VLESS_URI)
            finally:
                mod.STATE_DIR = orig_state
                mod.LEGACY_STATE_DIR = orig_legacy
                mod.CONFIG_FILE = orig_cfg

    def test_request_header_encoding(self) -> None:
        node = mod.parse_vless_uri(SAMPLE_VLESS_URI)
        hdr_domain = mod.build_vless_request_header(node, "example.com", 443)
        self.assertEqual(hdr_domain[0], 0x00)
        self.assertEqual(hdr_domain[1:17], node.user_uuid.bytes)
        self.assertEqual(hdr_domain[17:19], b"\x00\x01")
        self.assertEqual(struct.unpack("!H", hdr_domain[19:21])[0], 443)
        self.assertEqual(hdr_domain[21], 0x02)
        self.assertEqual(hdr_domain[22], len(b"example.com"))
        self.assertEqual(hdr_domain[23:], b"example.com")

        hdr_v4 = mod.build_vless_request_header(node, "8.8.8.8", 53)
        self.assertEqual(hdr_v4[21], 0x01)
        self.assertEqual(hdr_v4[22:], ipaddress.IPv4Address("8.8.8.8").packed)

        hdr_v6 = mod.build_vless_request_header(node, "2001:4860:4860::8888", 443)
        self.assertEqual(hdr_v6[21], 0x03)
        self.assertEqual(hdr_v6[22:], ipaddress.IPv6Address("2001:4860:4860::8888").packed)

    def test_resolve_agent_names(self) -> None:
        self.assertEqual(mod._resolve_agent_names(None), ["agy", "claude", "codex", "cursor"])
        self.assertEqual(mod._resolve_agent_names(["antigravity", "claude-code", "codex", "cursor"]),
                         ["agy", "claude", "codex", "cursor"])
        self.assertEqual(mod._resolve_agent_names(["all"]), ["agy", "claude", "codex", "cursor"])
        with self.assertRaises(ValueError):
            mod._resolve_agent_names(["unknown-tool"])

    def test_wrap_and_unwrap_regular_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            orig_state = mod.STATE_DIR
            orig_wrapped = mod.WRAPPED_FILE
            mod.STATE_DIR = tmp_path / ".state"
            mod.WRAPPED_FILE = mod.STATE_DIR / "wrapped.json"
            try:
                # 1. Regular binary (e.g. claude)
                bin_dir = tmp_path / "bin"
                bin_dir.mkdir()
                claude_bin = bin_dir / "claude"
                claude_bin.write_text("#!/bin/sh\necho real-claude\n", encoding="utf-8")
                os.chmod(claude_bin, 0o755)

                self.assertTrue(mod._wrap_one(claude_bin, "127.0.0.1", 17890))
                self.assertTrue(mod._is_our_wrapper(claude_bin))
                self.assertTrue((bin_dir / "claude.real").exists())
                self.assertIn('BIN_NAME="claude"', claude_bin.read_text(encoding="utf-8"))

                # Idempotent re-wrap does not overwrite .real
                self.assertTrue(mod._wrap_one(claude_bin, "127.0.0.1", 17891))
                self.assertIn("real-claude", (bin_dir / "claude.real").read_text(encoding="utf-8"))

                self.assertTrue(mod._unwrap_one(claude_bin))
                self.assertFalse(mod._is_our_wrapper(claude_bin))
                self.assertFalse((bin_dir / "claude.real").exists())
                self.assertIn("real-claude", claude_bin.read_text(encoding="utf-8"))

                # 2. Relative symlink (e.g. npm global codex -> ../lib/codex.js)
                lib_dir = tmp_path / "lib"
                lib_dir.mkdir()
                real_js = lib_dir / "codex.js"
                real_js.write_text("#!/usr/bin/env node\n", encoding="utf-8")
                os.chmod(real_js, 0o755)
                codex_link = bin_dir / "codex"
                os.symlink("../lib/codex.js", codex_link)

                self.assertTrue(mod._wrap_one(codex_link, "127.0.0.1", 17890))
                self.assertFalse(codex_link.is_symlink())
                self.assertTrue(mod._is_our_wrapper(codex_link))
                codex_real = bin_dir / "codex.real"
                self.assertTrue(codex_real.is_symlink())
                self.assertEqual(os.readlink(codex_real), "../lib/codex.js")

                self.assertTrue(mod._unwrap_one(codex_link))
                self.assertTrue(codex_link.is_symlink())
                self.assertEqual(os.readlink(codex_link), "../lib/codex.js")
                self.assertFalse(codex_real.is_symlink())
            finally:
                mod.STATE_DIR = orig_state
                mod.WRAPPED_FILE = orig_wrapped

    def test_cursor_settings_configure_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            settings_path = tmp_path / "Cursor" / "User" / "settings.json"
            settings_path.parent.mkdir(parents=True)
            settings_path.write_text(
                json.dumps({"editor.fontSize": 14, "http.proxy": "http://127.0.0.1:9999"}, indent=2) + "\n",
                encoding="utf-8",
            )
            backup_path = tmp_path / "cursor_backup.json"

            self.assertTrue(mod._configure_cursor_settings(settings_path, "127.0.0.1", 17890, backup_path))
            updated = json.loads(settings_path.read_text(encoding="utf-8"))
            self.assertEqual(updated["http.proxy"], "http://127.0.0.1:17890")
            self.assertEqual(updated["http.proxySupport"], "override")
            self.assertEqual(updated["editor.fontSize"], 14)

            self.assertTrue(mod._restore_cursor_settings(backup_path))
            restored = json.loads(settings_path.read_text(encoding="utf-8"))
            self.assertEqual(restored["http.proxy"], "http://127.0.0.1:9999")
            self.assertNotIn("http.proxySupport", restored)
            self.assertEqual(restored["editor.fontSize"], 14)
            self.assertFalse(backup_path.exists())

    def test_end_to_end_http_connect_plain_http_and_socks5(self) -> None:
        async def run() -> None:
            recorded_targets = []
            test_uuid = uuid.UUID("00000000-0000-4000-8000-000000000001")

            # 1. Start mock target echo server
            echo_srv = await asyncio.start_server(_mock_target_echo_server, "127.0.0.1", 0)
            echo_port = echo_srv.sockets[0].getsockname()[1]

            # 2. Start mock upstream server (security=none for loopback test without cert generation)
            upstream_srv = await asyncio.start_server(
                lambda r, w: _mock_upstream_server(r, w, test_uuid, recorded_targets),
                "127.0.0.1",
                0,
            )
            upstream_port = upstream_srv.sockets[0].getsockname()[1]

            # 3. Start local proxy pointing at the mock upstream server
            uri = f"vless://{test_uuid}@127.0.0.1:{upstream_port}?encryption=none&security=none&type=tcp&headerType=none#TEST"
            node = mod.parse_vless_uri(uri)
            proxy = mod.VlessLocalProxyServer(node=node, listen_host="127.0.0.1", listen_port=0)
            await proxy.start()

            try:
                # A. Test HTTP CONNECT (use non-loopback domain so it goes through upstream, not direct bypass)
                r, w = await asyncio.open_connection("127.0.0.1", proxy.bound_port)
                w.write(f"CONNECT fake.google.test:{echo_port} HTTP/1.1\r\nHost: fake.google.test:{echo_port}\r\n\r\n".encode())
                await w.drain()
                head = await r.readuntil(b"\r\n\r\n")
                self.assertIn(b"200 Connection Established", head)
                w.write(b"PING_CONNECT")
                await w.drain()
                reply = await r.read(1024)
                self.assertEqual(reply, b"ECHO:PING_CONNECT")
                w.close()
                await w.wait_closed()

                # B. Test plain HTTP proxy
                r, w = await asyncio.open_connection("127.0.0.1", proxy.bound_port)
                w.write(
                    f"GET http://fake.http.test:{echo_port}/hello HTTP/1.1\r\n"
                    f"Host: fake.http.test:{echo_port}\r\n"
                    f"Proxy-Connection: keep-alive\r\n\r\n".encode()
                )
                await w.drain()
                resp = await r.read(4096)
                self.assertIn(b"HTTP/1.1 200 OK", resp)
                self.assertTrue(resp.endswith(b"HELLO"))
                w.close()
                await w.wait_closed()

                # C. Test SOCKS5 CONNECT (domain type)
                r, w = await asyncio.open_connection("127.0.0.1", proxy.bound_port)
                w.write(b"\x05\x01\x00")
                await w.drain()
                self.assertEqual(await r.readexactly(2), b"\x05\x00")
                domain = b"fake.socks.test"
                w.write(b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + struct.pack("!H", echo_port))
                await w.drain()
                socks_resp = await r.readexactly(10)
                self.assertEqual(socks_resp[:2], b"\x05\x00")
                w.write(b"PING_SOCKS5")
                await w.drain()
                reply = await r.read(1024)
                self.assertEqual(reply, b"ECHO:PING_SOCKS5")
                w.close()
                await w.wait_closed()

                self.assertEqual(
                    recorded_targets,
                    [
                        ("fake.google.test", echo_port),
                        ("fake.http.test", echo_port),
                        ("fake.socks.test", echo_port),
                    ],
                )
            finally:
                await proxy.stop()
                upstream_srv.close()
                await upstream_srv.wait_closed()
                echo_srv.close()
                await echo_srv.wait_closed()

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
