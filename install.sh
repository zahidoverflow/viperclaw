#!/usr/bin/env bash
# ViperClaw Fresh-PC Auto-Installer & Harness Setup Script
# Installs ViperClaw (zero third-party runtime dependencies) and auto-configures
# OpenCode, Google Antigravity, Claude Code, OpenAI Codex, and Cursor.
set -euo pipefail

REPO_URL="${VIPERCLAW_REPO:-https://github.com/zahidoverflow/viperclaw.git}"
TARGET="${VIPERCLAW_TARGET:-all}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Error: python3 (>= 3.10) is required to install ViperClaw." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/pyproject.toml" ] && [ -d "$SCRIPT_DIR/src/viperclaw" ]; then
  echo "[viperclaw] Installing from local checkout: $SCRIPT_DIR"
  "$PYTHON_BIN" -m pip install --user -e "$SCRIPT_DIR"
else
  echo "[viperclaw] Installing from $REPO_URL"
  "$PYTHON_BIN" -m pip install --user "git+${REPO_URL}"
fi

# Ensure user local bin is on PATH for the current shell
USER_BIN="$("$PYTHON_BIN" -c 'import site, pathlib; print(pathlib.Path(site.USER_BASE) / "bin")')"
export PATH="${USER_BIN}:${PATH}"

echo "[viperclaw] Running auto-setup for target=${TARGET} (includes OpenCode, Antigravity, Claude Code, Codex & Cursor)..."
viperclaw setup --target "$TARGET"
echo "[viperclaw] Setup complete! Restart your AI coding harness (OpenCode / Antigravity / Claude Code / Codex / Cursor) to load all 72 skills and 17 MCP tools."
