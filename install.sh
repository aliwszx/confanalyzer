#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_USER="${SUDO_USER:-$USER}"

if [ -z "${TARGET_USER:-}" ]; then
    echo "[!] Could not determine target user."
    exit 1
fi

echo "[+] Installing confanalyzer v1.0.2 for user: $TARGET_USER"

install_pkg() {
    if command -v apt >/dev/null 2>&1; then
        apt update -y
        apt install -y "$@"
    else
        echo "[!] apt not found. Please install manually: $*"
        exit 1
    fi
}

if ! command -v pipx >/dev/null 2>&1; then
    echo "[+] pipx not found, installing..."
    install_pkg pipx
fi

if ! command -v rsync >/dev/null 2>&1; then
    echo "[+] rsync not found, installing..."
    install_pkg rsync
fi

TARGET_HOME="$(eval echo "~$TARGET_USER")"
BUILD_PARENT="$(mktemp -d /tmp/confanalyzer-build-XXXXXX)"

cleanup() {
    rm -rf "$BUILD_PARENT"
}
trap cleanup EXIT

echo "[+] Preparing temporary build directory..."
rsync -a --delete \
    --exclude '.git' \
    --exclude '.venv' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    "$SCRIPT_DIR"/ "$BUILD_PARENT"/src/

if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    echo "[+] Installing with pipx as user: $SUDO_USER"
    chown -R "$SUDO_USER":"$SUDO_USER" "$BUILD_PARENT"
    sudo -H -u "$SUDO_USER" bash -lc "
        cd '$BUILD_PARENT/src' && \
        pipx uninstall confanalyzer >/dev/null 2>&1 || true && \
        pipx install . --force && \
        pipx ensurepath
    "
else
    echo "[+] Installing with pipx as current user: $TARGET_USER"
    pipx uninstall confanalyzer >/dev/null 2>&1 || true
    pipx install "$BUILD_PARENT/src" --force
    pipx ensurepath
fi

if [ "$TARGET_USER" = "root" ] && [ "$(id -u)" -eq 0 ]; then
    BIN_PATH="/root/.local/bin/confanalyzer"
else
    BIN_PATH="$TARGET_HOME/.local/bin/confanalyzer"
fi

if [ ! -f "$BIN_PATH" ]; then
    echo "[!] Launcher not found at $BIN_PATH"
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    ln -sf "$BIN_PATH" /usr/local/bin/confanalyzer
    hash -r 2>/dev/null || true
    echo "[+] Global launcher linked at /usr/local/bin/confanalyzer"
else
    echo "[+] User-local launcher available at $BIN_PATH"
    echo "[+] Make sure \$HOME/.local/bin is in your PATH."
fi

echo "[+] Installation complete."
echo "[+] Run: confanalyzer --help"
