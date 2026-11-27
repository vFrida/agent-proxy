# Agent Proxy (`agent-proxy`)

English | [简体中文](README.zh-CN.md)

Zero dependencies (Python 3 standard library only, no extra proxy client): turns an encrypted upstream node into a local **HTTP / HTTPS / SOCKS5 mixed proxy**, and uniformly wraps **Antigravity (`agy`), Claude Code (`claude`), OpenAI Codex (`codex`), Cursor (`cursor`)** plus any other CLI dev tool.

It listens on `127.0.0.1:17890` by default (both `http://` and `socks5h://`); loopback and intranet addresses are connected directly.

---

## Requirements

- macOS / Linux
- Python 3 (tested on 3.9+)
- No root required; only listens on `127.0.0.1`

## Quick Start

Configure your own upstream VLESS node first: running `wrap` or `start -d` without a saved config prompts for input and saves it to `~/.agent-proxy/config.json` (you can also pass `--uri` or the `AGENT_PROXY_URI` env var).

```bash
cd ~/agent-proxy

./agent-proxy list                  # Show detected tools and their wrap status
./agent-proxy wrap                  # Prompts for node URI on first use, then wraps every detected tool
./agent-proxy wrap agy claude codex # Or wrap only the specified tools
```

Once wrapped, running `agy`, `claude`, `codex` or `cursor` automatically checks whether the local proxy is up (starting it if needed) and injects the proxy environment variables.

To avoid touching any binary, use `run` to run a command through the proxy on demand:

```bash
./agent-proxy run claude            # Run Claude Code through the proxy temporarily
./agent-proxy run codex             # Run Codex through the proxy temporarily
eval "$(./agent-proxy env)"         # Export proxy env vars into the current shell session
```

> **Already-running processes are not affected**: their environment is fixed at launch (e.g. a long-lived IDE `agy --hub`). If it is safe to restart them, run `./agent-proxy wrap --restart`, or use `Developer: Reload Window` / reopen the session in your IDE.

---

## Supported Tools

| Name | Coverage | How it is wrapped |
| --- | --- | --- |
| `agy` (alias `antigravity`) | `PATH`, `~/.local/bin/agy`, `~/.gemini/bin/agy` | CLI wrapper script (also covers IDE plugin paths) |
| `claude` (alias `claude-code`) | `PATH`, `~/.local/bin/claude`, `~/.claude/local/claude`, Homebrew / npm paths | CLI wrapper (symlink-safe) |
| `codex` (alias `openai-codex`) | `PATH`, `~/.local/bin/codex`, Homebrew / npm / cargo paths | CLI wrapper (symlink-safe) |
| `cursor` | `cursor` CLI | CLI wrapper (symlink-safe) |
| Any other CLI | Any path | `wrap --bin /path/to/cmd`, `run <cmd>` |

---

## Commands

| Command | Description |
| --- | --- |
| `./agent-proxy list` | List supported tools, detected install paths, and current wrap status |
| `./agent-proxy wrap [agents...]` | Wrap the given tools (all detected tools if omitted) |
| `./agent-proxy wrap --bin /path/to/cmd` | Additionally wrap a custom CLI path (repeatable) |
| `./agent-proxy wrap --restart` | Terminate running target processes so they pick up the new env |
| `./agent-proxy unwrap [agents...]` | Restore wrapper scripts (all if omitted) |
| `./agent-proxy run <cmd> [args...]` | Start the proxy and run any command with proxy env |
| `./agent-proxy env [--intranet-no-proxy] [--unset]` | Print `export` / `unset` statements to `eval` in the current shell |
| `./agent-proxy start -d` | Start the local proxy in the background (default `127.0.0.1:17890`) |
| `./agent-proxy start` | Start the local proxy in the foreground (add `-v` for connection logs) |
| `./agent-proxy status` | Show proxy status, PID, port, upstream node, and log path |
| `./agent-proxy stop` | Stop the background proxy |

Common `start` options: `--uri <uri>` (switch node temporarily), `--save` (persist as default), `--port`, `--insecure` (skip upstream certificate verification).

---

## Changing the Node

Persistent config lives in `~/.agent-proxy/config.json` (the legacy `~/.antigravity-vless-proxy/config.json` is also read):

```json
{ "upstream_uri": "..." }
```

Or switch and save from the command line:

```bash
./agent-proxy stop
./agent-proxy start -d --save --uri '<node-uri>'
```

> The daemon reuses an existing process when the same host:port is already listening, so run `stop` before switching nodes.

---

## How It Works

1. **Zero-dependency local mixed proxy**: implements encrypted TLS tunnel forwarding natively and serves HTTP `CONNECT` (HTTPS / HTTP/2 / gRPC), plain HTTP and SOCKS5 locally; `localhost / 127.0.0.1 / ::1 / *.local` are connected directly so local traffic is unaffected.
2. **Symlink-safe CLI wrapping**: `wrap` renames the original entry point (binary or npm/Homebrew symlink) in place to `<name>.real` and generates a thin shell wrapper that:
   1. checks `127.0.0.1:17890` and runs `agent-proxy start -d` if it is not up (waits up to 5s);
   2. injects `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` / `NODE_USE_ENV_PROXY=1` (works with Go, Node.js, Python and Rust tools);
   3. `exec <name>.real "$@"`, passing through arguments, stdio and exit code unchanged.
3. **CLI only**: the tool takes effect purely by wrapping CLIs / injecting env vars; it never launches or modifies any desktop (GUI) app. Configure the proxy in the desktop app's settings yourself.

---

## Files

| Path | Description |
| --- | --- |
| `agent-proxy` | CLI launcher (`exec python3 agent_proxy.py "$@"`) |
| `agent_proxy.py` | Local proxy and multi-tool wrapping implementation |
| `test_agent_proxy.py` | Unit tests and loopback integration tests |
| `~/.agent-proxy/config.json` | Default upstream node config |
| `~/.agent-proxy/wrapped.json` | Registry of wrapped paths (used by `unwrap`) |
| `~/.agent-proxy/proxy.pid` / `state.json` | Daemon state |
| `~/.agent-proxy/proxy.log` | Proxy runtime log |

Self-test: `python3 -m unittest test_agent_proxy -v`

---

## FAQ

| Symptom | Fix |
| --- | --- |
| CLI runs but network errors / timeouts | Run `./agent-proxy list` to confirm `WRAPPED`, and `./agent-proxy status` to confirm `RUNNING` |
| `Status: STOPPED` | `./agent-proxy start -d`; or just invoke a wrapped CLI to auto-start it |
| Stops proxying after a tool self-update | Re-run `./agent-proxy wrap <tool>` to re-wrap it |
| Not effective in the current session after wrapping | Old processes have a fixed env: `./agent-proxy wrap --restart` or restart the IDE / Reload Window |
| Port already in use | `lsof -nP -iTCP:17890`; or start with `--port <new-port>` and re-run `wrap --port <new-port>` |
| Full uninstall | `./agent-proxy unwrap` (restores all wrapper scripts) |
