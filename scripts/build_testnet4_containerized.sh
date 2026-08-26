#!/usr/bin/env bash
# ===========================================================================
#  SubZero Keyosk: Sprint 1.1 Testnet4 TDD Image Builder (x86_64 & RPi armv7)
# ===========================================================================
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$( cd "${DIR}/.." && pwd )"

echo "=================================================="
echo "    SUBZERO KEYOSK: BUILD TESTNET4 TDD IMAGES     "
echo "=================================================="

# Step 1: Compile Testnet4 CJS bundle
echo -e "\n[1/3] Building Testnet4 CJS Bundle (dist/tui_testnet4.cjs)..."
npm --prefix "${WORKSPACE_DIR}" run build:testnet4

# Step 2: Build PC UEFI Testnet4 Image (x86_64)
echo -e "\n[2/3] Building PC UEFI Testnet4 Image (dist/subzero-testnet4-pc.img)..."
"${DIR}/build_alpine_containerized.sh" "tui_testnet4.cjs" "subzero-testnet4-pc.img"

# Step 3: Build Raspberry Pi Testnet4 Image (armv7)
echo -e "\n[3/3] Building Raspberry Pi Testnet4 Image (dist/subzero-testnet4-rpi.img)..."
"${DIR}/build_rpi_containerized.sh" "tui_testnet4.cjs" "subzero-testnet4-rpi.img"

echo -e "\n=================================================="
echo " SUCCESS: Testnet4 TDD Suite Compiled!"
echo " 1. PC UEFI Image : ${WORKSPACE_DIR}/dist/subzero-testnet4-pc.img"
echo " 2. RPi ARM Image : ${WORKSPACE_DIR}/dist/subzero-testnet4-rpi.img"
echo "=================================================="
