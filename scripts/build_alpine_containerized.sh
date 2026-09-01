#!/bin/bash
# ===========================================================================
#  SubZero Alpine Kiosk — Containerized Build Wrapper
#  Mirrors buildroot-compiler/build.sh pattern.
#
#  Runs build_alpine_kiosk.sh inside a disposable Docker container.
#  The container gets --privileged for losetup/mount, but all damage
#  from trap bugs stays inside the container. The host is never at risk.
#
#  Usage: ./scripts/build_alpine_containerized.sh
#         (no sudo needed — Docker handles privileges internally)
# ===========================================================================
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$( cd "${DIR}/.." && pwd )"

echo "==========================================="
echo "  SubZero Alpine Builder (Containerized)   "
echo "==========================================="

TUI_BUNDLE="${1:-${TUI_BUNDLE:-tui.cjs}}"
IMG_NAME="${2:-${IMG_NAME:-subzero-alpine.img}}"

# Step 1: Ensure TUI is compiled
echo -e "\n[Step 1] Checking for compiled TUI application (${TUI_BUNDLE})..."
if [ ! -f "${WORKSPACE_DIR}/dist/${TUI_BUNDLE}" ]; then
    echo "Fatal: dist/${TUI_BUNDLE} not found. Running npm run build:all..."
    npm --prefix "${WORKSPACE_DIR}" run build:all
fi

# Step 2: Build the Alpine compiler container
echo -e "\n[Step 2] Building Alpine builder Docker image..."
docker build -t subzero-alpine-compiler -f "${DIR}/Dockerfile.alpine" "${DIR}"

# Step 3: Run the build inside the container
echo -e "\n[Step 3] Running containerized Alpine build (${IMG_NAME})..."
mkdir -p "${WORKSPACE_DIR}/dist"

docker run --rm --privileged \
    -v "${WORKSPACE_DIR}:/build" \
    -v "/dev:/dev" \
    -e SOURCE_DATE_EPOCH=1700000000 \
    -e TZ=UTC \
    -e "OUTPUT_DIR=/build/dist" \
    -e "TUI_BUNDLE=${TUI_BUNDLE}" \
    -e "IMG_NAME=${IMG_NAME}" \
    subzero-alpine-compiler

chmod 0666 "${WORKSPACE_DIR}/dist/${IMG_NAME}" 2>/dev/null || true

echo -e "\n==========================================="
echo " SUCCESS: Alpine kiosk image compiled (containerized)!"
echo " Image: ${WORKSPACE_DIR}/dist/${IMG_NAME}"
echo " Flash: python3 ./scripts/flash_drive.py"
echo "==========================================="
