#!/usr/bin/env bash
set -euo pipefail

# One-line installer for agent-proxy:
#   curl -fsSL https://raw.githubusercontent.com/vFrida/agent-proxy/main/install.sh | bash
#
# Optional flags (via `bash -s -- ...`):
#   --dir <PATH>         Install directory (default: ~/.agent-proxy)
#   --repo <OWNER/REPO>  GitHub repository (default: vFrida/agent-proxy)
#   --repo-url <URL>     Explicit git repository URL (overrides --repo)
#   --ref <REF>          Branch, tag, or commit (default: main)
#   --shell <SHELL>      Shell for PATH setup: auto|zsh|bash|fish|sh
#   --rc <PATH>          Explicit shell rc file for PATH setup
#   --no-path            Skip adding install directory to PATH
#   -h, --help           Show this help message

DEFAULT_REPO="${AGENT_PROXY_REPO:-vFrida/agent-proxy}"
DEFAULT_REPO_URL="${AGENT_PROXY_REPO_URL:-}"
DEFAULT_REF="${AGENT_PROXY_REF:-main}"
DEFAULT_DIR="${AGENT_PROXY_DIR:-$HOME/.agent-proxy}"

usage() {
  cat <<'EOF'
Install or upgrade agent-proxy via git clone.

Usage:
  curl -fsSL https://raw.githubusercontent.com/vFrida/agent-proxy/main/install.sh | bash
  curl -fsSL https://raw.githubusercontent.com/vFrida/agent-proxy/main/install.sh | bash -s -- [options]

Options:
  --dir <PATH>         Install directory (default: ~/.agent-proxy)
  --repo <OWNER/REPO>  GitHub repository (default: vFrida/agent-proxy)
  --repo-url <URL>     Explicit git repository URL (overrides --repo)
  --ref <REF>          Git branch, tag, or commit (default: main)
  --shell <SHELL>      Shell type for PATH setup: auto|zsh|bash|fish|sh
  --rc <PATH>          Explicit shell rc file for PATH setup
  --no-path            Skip adding install directory to shell PATH
  -h, --help           Show this help message

Environment variables:
  AGENT_PROXY_DIR       Override default install directory
  AGENT_PROXY_REPO      Override default GitHub repository
  AGENT_PROXY_REPO_URL  Override git clone URL directly
  AGENT_PROXY_REF       Override default git ref
EOF
}

color_enabled() {
  case "${AGENT_PROXY_COLOR:-}" in
    always) return 0 ;;
    never) return 1 ;;
  esac
  [ -z "${NO_COLOR:-}" ] || return 1
  [ "${TERM:-}" != "dumb" ] || return 1
  [ -t 1 ]
}

log() {
  if color_enabled; then
    printf '\033[36m[agent-proxy]\033[0m %s\n' "$*"
  else
    printf '[agent-proxy] %s\n' "$*"
  fi
}

err() {
  if color_enabled; then
    printf '\033[31m[agent-proxy] Error:\033[0m %s\n' "$*" >&2
  else
    printf '[agent-proxy] Error: %s\n' "$*" >&2
  fi
  exit 1
}

check_deps() {
  command -v git >/dev/null 2>&1 || err "git is required. Please install git and retry."
  command -v python3 >/dev/null 2>&1 || err "python3 is required (Python 3.9+)."
  if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
    local ver
    ver="$(python3 --version 2>&1 || true)"
    err "Python 3.9+ is required (found: ${ver:-unknown})."
  fi
}

is_dir_empty() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  [ -z "$(ls -A "$dir" 2>/dev/null)" ]
}

sync_repo() {
  local repo_url="$1"
  local ref="$2"
  local install_dir="$3"

  if [ -d "$install_dir/.git" ]; then
    log "Updating existing repository in $install_dir (${ref})..."
    git -C "$install_dir" remote set-url origin "$repo_url" 2>/dev/null || \
      git -C "$install_dir" remote add origin "$repo_url"
    if [ -f "$install_dir/.git/shallow" ]; then
      git -C "$install_dir" fetch --unshallow origin "$ref" 2>/dev/null || \
        git -C "$install_dir" fetch origin "$ref"
    else
      git -C "$install_dir" fetch origin "$ref"
    fi
    git -C "$install_dir" checkout -f -B "$ref" FETCH_HEAD
    return 0
  fi

  if [ ! -e "$install_dir" ] || is_dir_empty "$install_dir"; then
    [ -d "$install_dir" ] && rmdir "$install_dir" 2>/dev/null || true
    log "Cloning ${repo_url} (${ref}) into ${install_dir}..."
    if git clone --branch "$ref" "$repo_url" "$install_dir" 2>/dev/null; then
      return 0
    fi
    # Fallback for commit SHAs where `git clone --branch <sha>` is unsupported
    rm -rf "$install_dir"
    mkdir -p "$install_dir"
    git -C "$install_dir" init -q
    git -C "$install_dir" remote add origin "$repo_url"
    git -C "$install_dir" fetch origin "$ref"
    git -C "$install_dir" checkout -f FETCH_HEAD
    return 0
  fi

  # Non-empty existing directory without .git (e.g. ~/.agent-proxy already has config.json):
  # initialize git in place without deleting existing runtime state files.
  log "Existing directory detected at $install_dir; initializing git repo in place..."
  git -C "$install_dir" init -q
  git -C "$install_dir" remote set-url origin "$repo_url" 2>/dev/null || \
    git -C "$install_dir" remote add origin "$repo_url"
  git -C "$install_dir" fetch origin "$ref"
  git -C "$install_dir" checkout -f -B "$ref" FETCH_HEAD
}

main() {
  local repo="$DEFAULT_REPO"
  local repo_url="$DEFAULT_REPO_URL"
  local ref="$DEFAULT_REF"
  local install_dir="$DEFAULT_DIR"
  local shell_type="auto"
  local rc_path=""
  local no_path=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --dir)
        [ $# -ge 2 ] || err "--dir requires a path argument"
        install_dir="$2"
        shift 2
        ;;
      --repo)
        [ $# -ge 2 ] || err "--repo requires an OWNER/REPO argument"
        repo="$2"
        shift 2
        ;;
      --repo-url)
        [ $# -ge 2 ] || err "--repo-url requires a URL argument"
        repo_url="$2"
        shift 2
        ;;
      --ref)
        [ $# -ge 2 ] || err "--ref requires a branch/tag/commit argument"
        ref="$2"
        shift 2
        ;;
      --shell)
        [ $# -ge 2 ] || err "--shell requires an argument"
        shell_type="$2"
        shift 2
        ;;
      --rc)
        [ $# -ge 2 ] || err "--rc requires a path argument"
        rc_path="$2"
        shift 2
        ;;
      --no-path)
        no_path=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        err "Unknown option: $1 (run with --help for usage)"
        ;;
    esac
  done

  if [ -z "$repo_url" ]; then
    repo_url="https://github.com/${repo}.git"
  fi

  check_deps
  sync_repo "$repo_url" "$ref" "$install_dir"

  [ -f "$install_dir/agent-proxy" ] || err "Missing $install_dir/agent-proxy after clone"
  [ -f "$install_dir/agent_proxy.py" ] || err "Missing $install_dir/agent_proxy.py after clone"
  chmod 755 "$install_dir/agent-proxy" "$install_dir/agent_proxy.py"

  python3 -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1])' \
    "$install_dir/agent_proxy.py" || err "Syntax verification failed for agent_proxy.py"

  log "Installed to: $install_dir ($("$install_dir/agent-proxy" version 2>/dev/null || echo 'version unknown'))"

  if [ "$no_path" -eq 0 ]; then
    local install_args=(install --shell "$shell_type" --dir "$install_dir")
    if [ -n "$rc_path" ]; then
      install_args+=(--rc "$rc_path")
    fi
    "$install_dir/agent-proxy" "${install_args[@]}"
  else
    log "Skipped PATH setup (--no-path). Run directly with: $install_dir/agent-proxy"
  fi

  log "Done! Next step: run 'agent-proxy wrap' (or 'agent-proxy start -d') to configure your upstream node."
}

main "$@"
