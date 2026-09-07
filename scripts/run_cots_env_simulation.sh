#!/usr/bin/env bash
# ==============================================================================
# SUBZERO-RS COTS LAPTOP ENVIRONMENT & HARDWARE-CONSTRAINT TEST RUNNER
# ==============================================================================
# Simulates low-resource legacy COTS laptop constraints (single-core/dual-core,
# 1GB RAM, zero-swap amnesic tmpfs, throttled slow I/O) via Docker cgroups.
# ==============================================================================

set -euo pipefail

# Script directories and repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Configurable COTS resource constraints (defaults: 1.0 CPU, 1024MB RAM, no swap)
COTS_CPUS="${COTS_CPUS:-1.0}"
COTS_MEMORY="${COTS_MEMORY:-1024m}"
COTS_SWAP="${COTS_SWAP:-1024m}"          # memory == swap ensures zero swap usage
COTS_BLKIO_WEIGHT="${COTS_BLKIO_WEIGHT:-100}" # lowest cgroups blkio priority (10-1000)
DOCKER_IMAGE="${DOCKER_IMAGE:-messense/rust-musl-cross:x86_64-musl}"
TEST_TARGET="${TEST_TARGET:-cots_environment_suite}"

# Help / Usage
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [-- CARGO_TEST_ARGS...]

Runs the SubZero-rs COTS environment test suite under throttled hardware constraints.

Options:
  --single-core       Enforce 1.0 CPU core constraint (default)
  --dual-core         Enforce 2.0 CPU cores constraint
  --cpus <N>          Set custom CPU core quota (e.g. 0.5, 1.0, 2.0)
  --memory <SIZE>     Set custom memory limit (e.g. 512m, 1024m, 2048m)
  --suite <NAME>      Test suite to run (default: cots_environment_suite)
  -h, --help          Show this help message

Environment Variables:
  COTS_CPUS           CPU quota (default: 1.0)
  COTS_MEMORY         Memory limit (default: 1024m)
  COTS_SWAP           Memory+swap limit (default: 1024m)
  COTS_BLKIO_WEIGHT   Block I/O weight (default: 100)
  DOCKER_IMAGE        Docker build image (default: messense/rust-musl-cross:x86_64-musl)

Examples:
  $(basename "$0")
  $(basename "$0") --dual-core
  $(basename "$0") -- --nocapture test_cots_bounded_heap
EOF
    exit 0
}

EXTRA_CARGO_ARGS=()

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --single-core)
            COTS_CPUS="1.0"
            shift
            ;;
        --dual-core)
            COTS_CPUS="2.0"
            shift
            ;;
        --cpus)
            COTS_CPUS="$2"
            shift 2
            ;;
        --memory)
            COTS_MEMORY="$2"
            COTS_SWAP="$2"
            shift 2
            ;;
        --suite)
            TEST_TARGET="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        --)
            shift
            EXTRA_CARGO_ARGS=("$@")
            break
            ;;
        *)
            EXTRA_CARGO_ARGS+=("$1")
            shift
            ;;
    esac
done

echo "=================================================================="
echo " SUBZERO-RS: COTS LAPTOP ENVIRONMENT REGRESSION SIMULATOR"
echo "=================================================================="
echo " Target Architecture : x86_64-unknown-linux-musl (static COTS)"
echo " CPU Allocation      : ${COTS_CPUS} core(s)"
echo " Memory Ceiling      : ${COTS_MEMORY} (amnesic tmpfs RAM boundary)"
echo " Swap Allowance      : 0 MB (strict anti-swap memory locking)"
echo " Block I/O Weight    : ${COTS_BLKIO_WEIGHT} (throttled legacy USB/SD bus)"
echo " Docker Container    : ${DOCKER_IMAGE}"
echo " Test Target         : ${TEST_TARGET}"
echo " Host Working Tree   : ${REPO_ROOT}"
echo "=================================================================="

# Ensure docker daemon is accessible
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker command not found on host system." >&2
    exit 1
fi

START_TIME=$(date +%s)

# Construct cargo test execution command
CARGO_CMD=("cargo" "test" "--test" "${TEST_TARGET}")
if [[ ${#EXTRA_CARGO_ARGS[@]} -gt 0 ]]; then
    CARGO_CMD+=("${EXTRA_CARGO_ARGS[@]}")
else
    CARGO_CMD+=("--" "--nocapture")
fi

echo ""
echo ">> Launching isolated COTS container simulation..."
echo ">> Executing: ${CARGO_CMD[*]}"
echo ""

set +e
docker run --rm \
    --cpus="${COTS_CPUS}" \
    --memory="${COTS_MEMORY}" \
    --memory-swap="${COTS_SWAP}" \
    --blkio-weight="${COTS_BLKIO_WEIGHT}" \
    -v "${REPO_ROOT}:/home/rust/src" \
    "${DOCKER_IMAGE}" \
    "${CARGO_CMD[@]}"
EXIT_CODE=$?
set -e

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "=================================================================="
if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo " RESULT: SUCCESS (Exit Code: 0)"
    echo " All COTS laptop constraints & regression assertions PASSED."
    echo " Execution Duration: ${ELAPSED}s"
    echo "=================================================================="
    exit 0
else
    echo " RESULT: FAILURE (Exit Code: ${EXIT_CODE})"
    echo " One or more assertions failed under COTS resource constraints."
    echo " Execution Duration: ${ELAPSED}s"
    echo "=================================================================="
    exit "${EXIT_CODE}"
fi
