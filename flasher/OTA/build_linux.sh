#!/usr/bin/env bash
set -euo pipefail

# --------------------------------------------
# RNode-HaLow Flasher GUI build for Linux
# Builds single-file binary via PyInstaller
# --------------------------------------------

cd "$(dirname "$0")"

APP_PY="rnode-halow-flasher-gui.py"
VENV_DIR=".venv"
DIST_DIR="dist"
BUILD_DIR="build"
SPEC_NAME="rnode-halow-flasher-gui"

if [[ ! -f "$APP_PY" ]]; then
  echo "[!] '$APP_PY' not found in: $(pwd)"
  exit 1
fi

if [[ ! -d "modules" ]]; then
  echo "[!] 'modules/' folder not found in: $(pwd)"
  exit 1
fi

mkdir -p embedded_fw

PYTHON_BIN="python3"

# --- create venv (once) ---
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  echo "[*] Creating venv: $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

VPY="$VENV_DIR/bin/python"
VPIP="$VENV_DIR/bin/pip"

echo "[*] Upgrading pip/setuptools/wheel..."
"$VPY" -m pip install --upgrade pip setuptools wheel

if [[ -f "requirements.txt" ]]; then
  echo "[*] Installing requirements.txt..."
  "$VPIP" install -r requirements.txt
fi

echo "[*] Installing build deps (pyinstaller)..."
"$VPIP" install --upgrade pyinstaller

# --- clean old outputs ---
rm -rf "$DIST_DIR" "$BUILD_DIR" "${SPEC_NAME}.spec"

# --- build ---
echo "[*] Building..."
"$VPY" -m PyInstaller \
  --noconfirm \
  --clean \
  --onefile \
  --name "$SPEC_NAME" \
  --add-data "modules:modules" \
  --add-data "embedded_fw:embedded_fw" \
  --collect-all scapy \
  "$APP_PY"

echo
echo "[OK] Done:"
echo "    $(pwd)/$DIST_DIR/$SPEC_NAME"
echo
echo "Note:"
echo "  - Scapy raw send/sniff may require root/capabilities."
echo "  - If you want non-root run, you can do:"
echo "      sudo setcap cap_net_raw,cap_net_admin=eip ./$DIST_DIR/$SPEC_NAME"
echo

