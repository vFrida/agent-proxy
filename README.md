# Agent Proxy (`agent-proxy`)

零依赖（仅用 macOS 自带 Python 3 标准库，无需额外代理客户端）：把上游加密节点转为本地 **HTTP / HTTPS / SOCKS5 混合代理**，并支持统一接管 **Antigravity (`agy`)、Claude Code (`claude`)、OpenAI Codex (`codex`)、Cursor (`cursor` / `Cursor.app`)** 及任意其它 CLI / GUI 开发工具。

默认本地监听 `127.0.0.1:17890`（同时支持 `http://` 和 `socks5h://`），本机与内网地址自动直连。

---

## 环境要求

- macOS（Intel / Apple Silicon 均可）
- Python 3（系统自带即可，实测 3.9+）
- 不需要 root；只监听 `127.0.0.1`

## 快速开始

```bash
cd ~/agent-proxy

./agent-proxy list                  # 查看本机已检测到的工具与接管状态
./agent-proxy wrap                  # 一次性接管所有已检测到的工具（agy / claude / codex / cursor）
./agent-proxy wrap agy claude codex # 或只接管指定工具
```

接管之后，直接执行 `agy`、`claude`、`codex`、`cursor` 时都会自动检测本地代理是否在线（未启动会自动拉起），并自动注入代理环境变量。

不想改任何二进制，也可以用 `run` 或 `launch` 按需套代理运行：

```bash
./agent-proxy run claude            # 临时通过代理运行 Claude Code
./agent-proxy run codex             # 临时通过代理运行 Codex
./agent-proxy launch cursor         # 临时通过代理启动 Cursor.app（自动附带 Chromium 代理参数）
eval "$(./agent-proxy env)"         # 在当前终端会话临时导出代理环境变量
```

> **已经在跑的进程不会自动生效**：进程启动时环境已固定（如 IDE 常驻的 `agy --hub`、已打开的 Cursor 窗口）。确认可重启后执行 `./agent-proxy wrap --restart`，或在 IDE 里 `Developer: Reload Window` / 重启应用。

---

## 支持的工具

| 名称 | 覆盖范围 | 接管方式 |
| --- | --- | --- |
| `agy`（别名 `antigravity`） | `PATH`、`~/.local/bin/agy`、`~/.gemini/bin/agy` | CLI 包装脚本（同时覆盖 IDE 插件链路） |
| `claude`（别名 `claude-code`） | `PATH`、`~/.local/bin/claude`、`~/.claude/local/claude`、Homebrew / npm 路径；`Claude.app` | CLI 包装（兼容软链）+ `launch claude` |
| `codex`（别名 `openai-codex`） | `PATH`、`~/.local/bin/codex`、Homebrew / npm / cargo 路径 | CLI 包装（兼容软链） |
| `cursor` | `cursor` CLI + `Cursor.app` + `Cursor/User/settings.json` | CLI 包装 + 安全写入 `http.proxy`（可无损还原）+ `launch cursor` |
| 任意其它 CLI / App | 任意路径 | `wrap --bin /path/to/cmd`、`run <cmd>`、`launch <AppName>` |

---

## 命令一览

| 命令 | 说明 |
| --- | --- |
| `./agent-proxy list` | 列出支持的工具、检测到的安装路径及当前接管状态 |
| `./agent-proxy wrap [agents...]` | 接管指定工具（不填则接管全部已检测到的工具） |
| `./agent-proxy wrap --bin /path/to/cmd` | 额外包装其它自定义 CLI 路径（可重复） |
| `./agent-proxy wrap --gui` | 额外给 GUI 应用注入代理（LaunchAgent + `launchctl setenv`） |
| `./agent-proxy wrap --no-cursor-settings` | 包装 `cursor` 时不修改 Cursor 的 `settings.json` |
| `./agent-proxy wrap --restart` | 结束后台已在跑的目标进程，使其重启后生效 |
| `./agent-proxy unwrap [agents...]` | 还原包装脚本（不填则还原全部，并清除 Cursor 代理配置与 GUI 环境注入） |
| `./agent-proxy run <cmd> [args...]` | 自动拉起代理并带代理环境执行任意命令 |
| `./agent-proxy launch <app> [args...]` | 自动拉起代理并启动 macOS 桌面应用（如 `cursor`、`claude`） |
| `./agent-proxy env [--unset]` | 输出当前 shell 可 `eval` 的 `export` / `unset` 语句 |
| `./agent-proxy start -d` | 后台启动本地代理（默认 `127.0.0.1:17890`） |
| `./agent-proxy start` | 前台启动本地代理（可加 `-v` 看连接日志） |
| `./agent-proxy status` | 查看代理状态、PID、端口、上游节点、日志路径 |
| `./agent-proxy stop` | 停止后台代理 |

`start` 常用参数：`--uri <uri>`（临时换节点）、`--save`（写入默认配置）、`--port`、`--insecure`（跳过上游证书校验）。

---

## 更换节点

持久化配置位于 `~/.agent-proxy/config.json`（兼容读取旧版 `~/.antigravity-vless-proxy/config.json`）：

```json
{ "upstream_uri": "..." }
```

或直接通过命令行切换并保存：

```bash
./agent-proxy stop
./agent-proxy start -d --save --uri '<node-uri>'
```

> 守护进程按「同 host:port 且已监听」复用已有进程，换节点前请先执行 `stop`。

---

## 工作原理

1. **零依赖本地混合代理**：原生实现加密 TLS 隧道转发，本地同时提供 HTTP `CONNECT`（HTTPS / HTTP/2 / gRPC）、普通 HTTP 与 SOCKS5；`localhost / 127.0.0.1 / ::1 / *.local` 自动直连，不影响本地通信。
2. **兼容软链的 CLI 包装**：`wrap` 将原入口（二进制或 npm/Homebrew 软链）原地改名为 `<name>.real` 并生成薄 shell 包装脚本：
   1. 检测 `127.0.0.1:17890`，未启动时自动执行 `agent-proxy start -d` 拉起（最多等 5s）；
   2. 注入 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` / `NODE_USE_ENV_PROXY=1`（同时兼容 Go、Node.js、Python、Rust 工具）；
   3. `exec <name>.real "$@"`，参数、stdio、退出码原样透传。
3. **桌面应用支持**：对 Cursor 等 Electron 应用同时支持 `settings.json` 自动备份写入、`launch cursor` 注入 `--proxy-server` 参数，以及 `wrap --gui` 全局 LaunchAgent 环境注入（内置内网域与私有网段 `NO_PROXY`）。

---

## 目录与文件

| 路径 | 说明 |
| --- | --- |
| `agent-proxy` | CLI 启动器（`exec python3 agent_proxy.py "$@"`） |
| `agent_proxy.py` | 本地代理与多工具接管实现 |
| `test_agent_proxy.py` | 单元测试与本地回环集成测试 |
| `~/.agent-proxy/config.json` | 默认上游节点配置 |
| `~/.agent-proxy/wrapped.json` | 已包装路径记录（供 `unwrap` 完整还原） |
| `~/.agent-proxy/cursor_settings_backup.json` | Cursor 原始代理配置备份 |
| `~/.agent-proxy/proxy.pid` / `state.json` | 守护进程状态 |
| `~/.agent-proxy/proxy.log` | 代理运行日志 |

自测：`python3 -m unittest test_agent_proxy -v`

---

## 常见问题

| 现象 | 处理 |
| --- | --- |
| CLI 运行正常但网络报错 / 超时 | 执行 `./agent-proxy list` 确认状态为 `WRAPPED`，`./agent-proxy status` 确认 `RUNNING` |
| `Status: STOPPED` | `./agent-proxy start -d`；或直接调用已包装的 CLI 自动拉起 |
| 工具自更新后不走代理了 | 重跑一次 `./agent-proxy wrap <tool>` 即可重新接管 |
| 接管后当前会话仍未生效 | 旧进程环境已固定：`./agent-proxy wrap --restart` 或重启 IDE / Reload Window |
| Cursor / Claude Desktop 等 GUI 不走代理 | 用 `./agent-proxy launch cursor` 启动，或执行 `./agent-proxy wrap --gui` 后重开应用 |
| 端口被占用 | `lsof -nP -iTCP:17890`；或改用 `--port <新端口>` 启动并重新 `wrap --port <新端口>` |
| 彻底卸载 | `./agent-proxy unwrap`（还原全部包装脚本、Cursor 配置并清除 LaunchAgent） |
