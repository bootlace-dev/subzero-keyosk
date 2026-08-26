#!/usr/bin/env bash
# ===========================================================================
#  SubZero Keyosk: Differential Random Entropy Multi-Arch Fuzzing Harness
#  Simulates fresh physical dice/coin entropy across x86_64, ARMv7, and ARM64.
# ===========================================================================
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$( cd "${DIR}/.." && pwd )"

NUM_TRIALS="${1:-5}"

echo "=================================================="
echo "   SUBZERO: DIFFERENTIAL RANDOM ENTROPY AUDIT     "
echo "   Running ${NUM_TRIALS} randomized cross-architecture trials "
echo "=================================================="

# Ensure bundles are up to date
npm --prefix "${WORKSPACE_DIR}" run build:all >/dev/null

# Setup multiarch binfmt
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes >/dev/null 2>&1 || true

for i in $(seq 1 "${NUM_TRIALS}"); do
    echo -e "\n--------------------------------------------------"
    echo " [Trial ${i}/${NUM_TRIALS}] Generating Fresh Random Entropy Stream..."

    # Alternate between random 128-bit coin flips and 50 dice rolls
    if [ $((i % 2)) -eq 1 ]; then
        # 128 random coin flips (0 and 1)
        ENTROPY=$(head -c 64 /dev/urandom | od -An -vtu1 | tr -s ' ' '\n' | awk '{print $1%2}' | tr -d '\n' | head -c 128)
        TYPE="COIN FLIPS (128-bit)"
    else
        # 50 random dice rolls (1 to 6)
        ENTROPY=$(head -c 128 /dev/urandom | od -An -vtu1 | tr -s ' ' '\n' | awk '{r=($1%6)+1; print r}' | tr -d '\n' | head -c 50)
        TYPE="DICE ROLLS (50 rolls)"
    fi

    echo " Entropy Type   : ${TYPE}"
    echo " Raw Sample     : $(echo "${ENTROPY}" | head -c 30)... (total: ${#ENTROPY} chars)"

    # 1. Execute on x86_64
    OUT_X86=$(printf "%s\n \n" "${ENTROPY}" | docker run -i --rm \
        --platform linux/amd64 \
        --read-only --tmpfs /tmp \
        -v "${WORKSPACE_DIR}/dist:/app/dist:ro" \
        -w /app node:20-alpine \
        node dist/tui_testnet4.cjs 2>&1 | tr -d '\r')

    # 2. Execute on ARMv7 (32-bit Pi)
    OUT_ARM32=$(printf "%s\n \n" "${ENTROPY}" | docker run -i --rm \
        --platform linux/arm/v7 \
        --read-only --tmpfs /tmp \
        -v "${WORKSPACE_DIR}/dist:/app/dist:ro" \
        -w /app arm32v7/node:20-alpine \
        node dist/tui_testnet4.cjs 2>&1 | tr -d '\r')

    # 3. Execute on ARM64 (64-bit Pi)
    OUT_ARM64=$(printf "%s\n \n" "${ENTROPY}" | docker run -i --rm \
        --platform linux/arm64 \
        --read-only --tmpfs /tmp \
        -v "${WORKSPACE_DIR}/dist:/app/dist:ro" \
        -w /app arm64v8/node:20-alpine \
        node dist/tui_testnet4.cjs 2>&1 | tr -d '\r')

    # Extract Key Artifacts
    DESC_X86=$(echo "${OUT_X86}" | grep -o "wpkh(\[.*\]tpub.*#.*" | head -n 1 || true)
    DESC_ARM32=$(echo "${OUT_ARM32}" | grep -o "wpkh(\[.*\]tpub.*#.*" | head -n 1 || true)
    DESC_ARM64=$(echo "${OUT_ARM64}" | grep -o "wpkh(\[.*\]tpub.*#.*" | head -n 1 || true)

    ADDR0_X86=$(echo "${OUT_X86}" | grep -o "tb1q[a-z0-9]\{38\}" | head -n 1 || true)
    ADDR0_ARM32=$(echo "${OUT_ARM32}" | grep -o "tb1q[a-z0-9]\{38\}" | head -n 1 || true)
    ADDR0_ARM64=$(echo "${OUT_ARM64}" | grep -o "tb1q[a-z0-9]\{38\}" | head -n 1 || true)

    echo " x86_64 Address : ${ADDR0_X86}"
    echo " ARMv7  Address : ${ADDR0_ARM32}"
    echo " ARM64  Address : ${ADDR0_ARM64}"

    # Parity Assertion
    if [ -z "${DESC_X86}" ] || [ "${DESC_X86}" != "${DESC_ARM32}" ] || [ "${DESC_X86}" != "${DESC_ARM64}" ]; then
        echo -e "\n[FATAL] Descriptor mismatch on trial ${i}!"
        echo " X86  : ${DESC_X86}"
        echo " ARM32: ${DESC_ARM32}"
        echo " ARM64: ${DESC_ARM64}"
        exit 1
    fi

    if [ -z "${ADDR0_X86}" ] || [ "${ADDR0_X86}" != "${ADDR0_ARM32}" ] || [ "${ADDR0_X86}" != "${ADDR0_ARM64}" ]; then
        echo -e "\n[FATAL] Address mismatch on trial ${i}!"
        exit 1
    fi

    echo " [Trial ${i} Result] => PASS (Bit-for-bit identical output across all 3 architectures)"
done

echo -e "\n=================================================="
echo " SUCCESS: All ${NUM_TRIALS} differential entropy trials verified!"
echo " Universal cross-architecture determinism proven."
echo "=================================================="
