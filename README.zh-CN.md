# Agent Proxy (`agent-proxy`)

[English](README.md) | 简体中文

**专为 CLI AI 编程助手设计的轻量级零依赖代理工具**，支持 **Antigravity (`agy`)、Claude Code (`claude`)、OpenAI Codex (`codex`)、Cursor (`cursor`)** 及任意其它 CLI 开发工具。

仅依赖 Python 3 标准库（无需安装额外代理客户端），将上游加密节点转为本地 **HTTP / HTTPS / SOCKS5 混合代理**（默认监听 `127.0.0.1:17890`，本机与内网地址自动直连），并让被接管的 CLI 工具无感通过代理访问网络。

## 目标用途

在受限网络环境、远程 Linux / SSH 开发机，或不方便开启全局 VPN / 桌面代理客户端的办公电脑上，CLI 编程助手经常面临无法直连、超时，或全局代理误伤内网与其它应用的问题。`agent-proxy` 旨在解决这些场景：

- **仅针对指定 CLI 定向代理，不影响全局网络**：通过 `wrap` 只接管选定的 CLI 工具（或用 `run` 单次套代理），不修改系统代理设置，不干扰浏览器、本机服务与内网访问。
- **零外部客户端、无需 root 权限**：纯 Python 3 标准库实现，无需安装 Clash / Xray / sing-box，也无需 `sudo`，适合无界面的远程服务器、SSH 会话和权限受限的开发机。
- **一次配置，日常无感使用**：接管后照常直接运行 `agy`、`claude`、`codex`、`cursor` 即可，包装脚本会自动按需拉起本地代理并注入兼容 Go / Node.js（含 `NODE_USE_ENV_PROXY=1`）/ Python / Rust 工具的代理环境变量。
- **随时可还原、仅面向 CLI**：执行 `agent-proxy unwrap` 即可原地恢复原始可执行文件或软链；不会修改系统全局代理或任何桌面（GUI）应用。

具体场景：

| 场景 | 命令 |
| --- | --- |
| 让所有 AI 编码 CLI 长期走代理 | `agent-proxy wrap`（执行一次即可） |
| 只让部分工具走代理 | `agent-proxy wrap claude codex` 或 `agent-proxy wrap --bin /path/to/tool` |
| 不改动任何程序，临时试一次 | `agent-proxy run <cmd>` 或 `eval "$(agent-proxy env)"` |
| 切换上游节点 | `agent-proxy start -d --uri 'vless://...' --save`（守护进程自动重启） |
| 排查当前状态 | `agent-proxy status`、`agent-proxy list`、`~/.agent-proxy/proxy.log` |
| 全部还原 | `agent-proxy unwrap` |

**适用范围与限制**：它不是 VPN/TUN 客户端，也不是规则化或多节点路由器，不转发 UDP/QUIC。内置引擎只支持 **VLESS over TCP + `security=tls|none`**（不支持 `ws` / `grpc` / `xhttp`），这类传输请使用 xray 或 sing-box。回环地址与内网域名始终经 `NO_PROXY` 直连。

---

## 环境要求

- macOS / Linux
- Python 3（实测 3.9+）
- 不需要 root；只监听 `127.0.0.1`

## 快速开始

### 一键安装（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/vFrida/agent-proxy/main/install.sh | bash
```

脚本会默认 `git clone` 到 `~/.agent-proxy` 并加入 Shell `PATH`（新终端自动生效；当前终端若仍找不到 `agent-proxy`，可按安装器输出的 rc 文件执行一次 `source`）。对已有安装重复执行时会拒绝覆盖未提交的本地改动，除非显式传入 `--force`。随后即可直接运行：

```bash
agent-proxy list                  # 查看本机已检测到的工具与接管状态
agent-proxy wrap                  # 首次会提示输入节点 URI，然后一次性接管所有已检测到的工具
agent-proxy wrap agy claude codex # 或只接管指定工具
```

### 或从本地仓库直接运行

首次使用前需配置你自己的上游 VLESS 节点：直接执行 `wrap` 或 `start -d` 时若尚未配置，会自动提示输入并保存到 `~/.agent-proxy/config.json`（也可通过 `--uri` 或环境变量 `AGENT_PROXY_URI` 传入）。

```bash
cd ~/agent-proxy

./agent-proxy install               # 可选：将 agent-proxy 目录添加到 PATH，之后可在任意目录直接运行
./agent-proxy list                  # 查看本机已检测到的工具与接管状态
./agent-proxy wrap                  # 首次会提示输入节点 URI，然后一次性接管所有已检测到的工具
./agent-proxy wrap agy claude codex # 或只接管指定工具
```

接管之后，直接执行 `agy`、`claude`、`codex`、`cursor` 时都会自动检测本地代理是否在线（未启动会自动拉起），并自动注入代理环境变量。

不想改任何二进制，也可以用 `run` 按需套代理运行：

```bash
./agent-proxy run claude            # 临时通过代理运行 Claude Code
./agent-proxy run codex             # 临时通过代理运行 Codex
eval "$(./agent-proxy env)"         # 在当前终端会话临时导出代理环境变量
```

> **已经在跑的进程不会自动生效**：进程启动时环境已固定（如 IDE 常驻的 `agy --hub`）。确认可重启后执行 `./agent-proxy wrap --restart`，或在 IDE 里 `Developer: Reload Window` / 重开会话。

---

## 支持的工具

| 名称 | 覆盖范围 | 接管方式 |
| --- | --- | --- |
| `agy`（别名 `antigravity`） | `PATH`、`~/.local/bin/agy`、`~/.gemini/bin/agy` | CLI 包装脚本（同时覆盖 IDE 插件链路） |
| `claude`（别名 `claude-code`） | `PATH`、`~/.local/bin/claude`、`~/.claude/local/claude`、Homebrew / npm 路径 | CLI 包装（兼容软链） |
| `codex`（别名 `openai-codex`） | `PATH`、`~/.local/bin/codex`、Homebrew / npm / cargo 路径 | CLI 包装（兼容软链） |
| `cursor` | `cursor` CLI | CLI 包装（兼容软链） |
| 任意其它 CLI | 任意路径 | `wrap --bin /path/to/cmd`、`run <cmd>` |

---

## 命令一览

| 命令 | 说明 |
| --- | --- |
| `./agent-proxy install` | 将 `agent-proxy` 目录添加到 Shell `PATH` 环境变量（支持 zsh / bash / fish；别名 `add-path`） |
| `./agent-proxy uninstall` | 移除由 `install` 添加的 `PATH` 环境变量配置（别名 `remove-path`） |
| `./agent-proxy version` | 查看当前版本（等于仓库总提交数；也支持 `-V` / `--version`） |
| `./agent-proxy update` | 从 GitHub 拉取最新版本（可加 `--restart` 自动重启守护进程、`--force` 覆盖本地修改） |
| `./agent-proxy list` | 列出支持的工具、检测到的安装路径及当前接管状态 |
| `./agent-proxy wrap [agents...]` | 接管指定工具（不填则接管全部已检测到的工具） |
| `./agent-proxy wrap --bin /path/to/cmd` | 额外包装其它自定义 CLI 路径（可重复） |
| `./agent-proxy wrap --restart` | 结束后台已在跑的目标进程，使其重启后生效 |
| `./agent-proxy unwrap [agents...]` | 还原包装脚本（不填则还原全部） |
| `./agent-proxy run <cmd> [args...]` | 自动拉起代理并带代理环境执行任意命令 |
| `./agent-proxy env [--intranet-no-proxy] [--unset]` | 输出当前 shell 可 `eval` 的 `export` / `unset` 语句 |
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
3. **仅面向 CLI**：工具只通过包装 CLI / 注入环境变量生效，不启动或修改任何桌面（GUI）应用；桌面应用需自行在设置中配置代理。

---

## 目录与文件

| 路径 | 说明 |
| --- | --- |
| `install.sh` | 一键 `curl \| bash` 安装与升级脚本 |
| `agent-proxy` | CLI 启动器（`exec python3 agent_proxy.py "$@"`） |
| `agent_proxy.py` | 本地代理与多工具接管实现 |
| `test_agent_proxy.py` | 单元测试与本地回环集成测试 |
| `~/.agent-proxy/config.json` | 默认上游节点配置 |
| `~/.agent-proxy/wrapped.json` | 已包装路径记录（供 `unwrap` 完整还原） |
| `~/.agent-proxy/proxy.pid` / `state.json` | 守护进程状态 |
| `~/.agent-proxy/proxy.log` | 代理运行日志 |

自测：`python3 -m unittest test_agent_proxy -v`

颜色：终端（TTY）下自动启用彩色输出；可用 `AGENT_PROXY_COLOR=always|never|auto` 控制，`NO_COLOR=1` 也可关闭颜色。

---

## 常见问题

| 现象 | 处理 |
| --- | --- |
| CLI 运行正常但网络报错 / 超时 | 执行 `./agent-proxy list` 确认状态为 `WRAPPED`，`./agent-proxy status` 确认 `RUNNING` |
| `Status: STOPPED` | `./agent-proxy start -d`；或直接调用已包装的 CLI 自动拉起 |
| 工具自更新后不走代理了 | 重跑一次 `./agent-proxy wrap <tool>` 即可重新接管 |
| 接管后当前会话仍未生效 | 旧进程环境已固定：`./agent-proxy wrap --restart` 或重启 IDE / Reload Window |
| 端口被占用 | `lsof -nP -iTCP:17890`；或改用 `--port <新端口>` 启动并重新 `wrap --port <新端口>` |
| 彻底卸载 | `./agent-proxy unwrap`（还原全部包装脚本） |
| 包装后的 CLI 提示 “local proxy ... unavailable” | 用 `./agent-proxy status` 和 `~/.agent-proxy/proxy.log` 排查；CLI 仍会在无代理的情况下启动 |
| 切换节点后流量仍走旧节点 | `./agent-proxy start -d` 检测到上游变化会自动重启守护进程 |
