#!/usr/bin/env bash
# ===========================================================================
#  Containerized Raspberry Pi ARM64 Image Builder Wrapper
# ===========================================================================
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$( cd "${DIR}/.." && pwd )"

TUI_BUNDLE="${1:-${TUI_BUNDLE:-tui.cjs}}"
IMG_NAME="${2:-${IMG_NAME:-subzero-rpi.img}}"

echo "=== [1/2] Building Containerized RPi aarch64 Environment ==="
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes >/dev/null 2>&1 || true
docker build -t subzero-rpi-builder -f "${DIR}/Dockerfile.rpi" "${DIR}"

echo "=== [2/2] Running build_rpi_kiosk.sh inside Container (${IMG_NAME}) ==="
docker run --rm --privileged \
    -v "${WORKSPACE_DIR}:/build" \
    -v "/dev:/dev" \
    -e SOURCE_DATE_EPOCH=1700000000 \
    -e TZ=UTC \
    -e "TUI_BUNDLE=${TUI_BUNDLE}" \
    -e "IMG_NAME=${IMG_NAME}" \
    subzero-rpi-builder
