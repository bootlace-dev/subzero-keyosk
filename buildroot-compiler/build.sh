#!/bin/bash
set -e

# Base directories
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$( cd "${DIR}/.." && pwd )"

echo "==========================================="
echo "     SubZero Deterministic Image Builder   "
echo "==========================================="

# Step 1: Ensure the HTML kiosk app is compiled
echo "\n[Step 1] Compiling HTML Kiosk Client..."
cd "${WORKSPACE_DIR}"
npm run build
cp "${WORKSPACE_DIR}/dist/index.html" "/dev/shm/subzero_signer_app.html"

# Step 2: Build the compiler Docker container
echo "\n[Step 2] Building Isolated Buildroot Docker Container..."
cd "${DIR}"
docker build -t subzero-compiler .

# Step 3: Run compilation container
echo "\n[Step 3] Running Deterministic Compilation (This takes time)..."
mkdir -p "${WORKSPACE_DIR}/dist"

docker run --rm \
    -v "/dev/shm/subzero_signer_app.html:/build/subzero_signer_app.html:ro" \
    -v "${DIR}/configs/subzero_defconfig:/build/subzero_defconfig:ro" \
    -v "${DIR}/board/subzero:/build/buildroot/board/subzero" \
    -v "${WORKSPACE_DIR}/dist:/build/output" \
    subzero-compiler

echo "\n==========================================="
echo " SUCCESS: Deterministic boot image compiled!"
echo " Image Target: ${WORKSPACE_DIR}/dist/subzero.img"
echo " Use scripts/flash_drive.py to write to SD card/USB."
echo "==========================================="
