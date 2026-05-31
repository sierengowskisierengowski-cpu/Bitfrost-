#!/usr/bin/env bash
set -euo pipefail

LINUXDEPLOY_URL="https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage"
LINUXDEPLOY_BIN="/usr/local/bin/linuxdeploy"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (for example: sudo $0)" >&2
  exit 1
fi

pacman -S --noconfirm webkit2gtk-4.1 gtk3 base-devel libayatana-appindicator fuse2

wget -O "${LINUXDEPLOY_BIN}" "${LINUXDEPLOY_URL}"
chmod +x "${LINUXDEPLOY_BIN}"

echo "Linux build dependencies installed. linuxdeploy path: ${LINUXDEPLOY_BIN}"
