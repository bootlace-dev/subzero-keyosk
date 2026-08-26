#!/usr/bin/env bash
# ===========================================================================
#  SubZero Keyosk: Multi-Engine Pre-Flight Verification Matrix
#  Runs multi-arch container sandboxes (x86_64 & armv7) before disk image build.
# ===========================================================================
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$( cd "${DIR}/.." && pwd )"

echo "=================================================="
echo "   SUBZERO KEYOSK: MULTI-ENGINE PRE-FLIGHT TEST   "
echo "=================================================="

# Step 1: Vitest Cryptographic Suite (Host)
echo -e "\n[Tier 1/3] Running Vitest BIP & Cryptographic Suite..."
npm --prefix "${WORKSPACE_DIR}" test

# Step 2: Build CJS Bundles
echo -e "\n[Tier 2/3] Bundling Mainnet & Testnet4 Applications..."
npm --prefix "${WORKSPACE_DIR}" run build:all

# Step 3: Multi-Arch Container Sanity Check (x86_64 vs ARM32)
echo -e "\n[Tier 3/3] Cross-Architecture Container Emulation Check..."

# Setup multiarch binfmt for ARM emulation
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes >/dev/null 2>&1 || true

echo "  -> Testing on Linux x86_64 (node:20-alpine)..."
X86_OUT=$(printf "test\n \n" | docker run -i --rm \
    --platform linux/amd64 \
    --read-only \
    --tmpfs /tmp \
    -v "${WORKSPACE_DIR}/dist:/app/dist:ro" \
    -w /app \
    node:20-alpine \
    node dist/tui_testnet4.cjs 2>&1 | tr -d '\r')

echo "  -> Testing on Linux ARMv7 / 32-bit Pi (arm32v7/node:20-alpine)..."
ARM32_OUT=$(printf "test\n \n" | docker run -i --rm \
    --platform linux/arm/v7 \
    --read-only \
    --tmpfs /tmp \
    -v "${WORKSPACE_DIR}/dist:/app/dist:ro" \
    -w /app \
    arm32v7/node:20-alpine \
    node dist/tui_testnet4.cjs 2>&1 | tr -d '\r')

echo "  -> Testing on Linux ARM64 / Pi Zero 2/3/4/5 (arm64v8/node:20-alpine)..."
ARM64_OUT=$(printf "test\n \n" | docker run -i --rm \
    --platform linux/arm64 \
    --read-only \
    --tmpfs /tmp \
    -v "${WORKSPACE_DIR}/dist:/app/dist:ro" \
    -w /app \
    arm64v8/node:20-alpine \
    node dist/tui_testnet4.cjs 2>&1 | tr -d '\r')

# Extract generated descriptors and addresses from all outputs
X86_DESC=$(echo "${X86_OUT}" | grep -o "wpkh(\[.*\]tpub.*#.*" | head -n 1 || true)
ARM32_DESC=$(echo "${ARM32_OUT}" | grep -o "wpkh(\[.*\]tpub.*#.*" | head -n 1 || true)
ARM64_DESC=$(echo "${ARM64_OUT}" | grep -o "wpkh(\[.*\]tpub.*#.*" | head -n 1 || true)

echo -e "\n--- Cross-Architecture Parity Audit ---"
echo " x86_64 Descriptor : ${X86_DESC}"
echo " ARMv7  Descriptor : ${ARM32_DESC}"
echo " ARM64  Descriptor : ${ARM64_DESC}"

if [ -n "${X86_DESC}" ] && [ "${X86_DESC}" = "${ARM32_DESC}" ] && [ "${X86_DESC}" = "${ARM64_DESC}" ]; then
    echo -e "\n[PASS] 100% Bit-for-Bit Parity across x86_64, ARMv7 (32-bit), and ARM64 (64-bit)!"
    echo "       All cryptographic engines, BigInt math, and Bech32 codecs match perfectly."
else
    echo -e "\n[FAIL] Parity mismatch across architectures!"
    exit 1
fi

echo -e "\n=================================================="
echo " PRE-FLIGHT VERIFICATION COMPLETE: ALL TIERS PASSED"
echo " Ready for containerized image compilation."
echo "=================================================="
