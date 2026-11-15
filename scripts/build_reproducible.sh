#!/usr/bin/env bash
# ==============================================================================
# SubZero v2.0 - Deterministic Container Build (`scripts/build_reproducible.sh`)
# ==============================================================================
#
# USAGE:
#   ./scripts/build_reproducible.sh                  # Build & verify against ./SHA256SUMS (if present)
#   ./scripts/build_reproducible.sh --verify         # Strictly verify against committed ./SHA256SUMS
#   ./scripts/build_reproducible.sh --update-manifest # Update root ./SHA256SUMS after intentional changes
#
# WHY THIS SCRIPT ENFORCES STRICT ORDERING & PATH REMAPPING:
# 1. Build Ordering Invariant (`WASM -> HTML Bundler -> musl TUI`):
#    `crates/subzero-tui/src/storage.rs` embeds `assets/decrypt.html` at compile
#    time via `include_str!()` so Partition 2 (`SUBZERO_EST`) USB recovery media
#    writes the exact same standalone decryptor shipped in `dist/decrypt.html`.
#    Therefore `subzero-wasm` + `scripts/bundle_html.py --sync-assets-decrypt`
#    MUST run BEFORE compiling `subzero-tui`.
# 2. Path-Independent Bit-for-Bit Reproducibility:
#    Rust panic locations, `secp256k1-sys` C objects, and GNU ld `.note.gnu.build-id`
#    sections normally embed the host working directory and Cargo cache path into
#    release binaries. Mounting the repo at `/work` inside Docker, remapping
#    `/work -> /subzero` and `/cargo-cache -> /cargo`, and passing `-Wl,--build-id=none`
#    guarantees identical SHA-256 digests whether built in `/tmp/audit-a` or
#    `/home/auditor/subzero-keyosk`, with or without `SUBZERO_CARGO_CACHE`.
# 3. Content-Addressed Builder Tag:
#    Default image tag includes the SHA-256 prefix of `Dockerfile.reproducible`
#    so any Dockerfile edit automatically triggers a fresh image build.
# ==============================================================================

set -euo pipefail

MODE="auto"
for arg in "$@"; do
    case "$arg" in
        --verify)
            MODE="verify"
            ;;
        --update-manifest)
            MODE="update"
            ;;
        -h|--help)
            echo "Usage: $0 [--verify | --update-manifest]"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (expected --verify or --update-manifest)" >&2
            exit 1
            ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE_HASH="$(sha256sum "$REPO_ROOT/Dockerfile.reproducible" | cut -c1-12)"
IMAGE_TAG="${SUBZERO_BUILDER_IMAGE:-subzero-repro-builder:${DOCKERFILE_HASH}}"
CARGO_CACHE_DIR="${SUBZERO_CARGO_CACHE:-}"

if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
    echo "[build] Building digest-pinned reproducible container ($IMAGE_TAG)..."
    docker build -f "$REPO_ROOT/Dockerfile.reproducible" -t "$IMAGE_TAG" "$REPO_ROOT"
fi

DOCKER_CACHE_ARGS=()
if [[ -n "$CARGO_CACHE_DIR" ]]; then
    mkdir -p "$CARGO_CACHE_DIR"
    DOCKER_CACHE_ARGS=(-v "$CARGO_CACHE_DIR:/cargo-cache")
fi

mkdir -p "$REPO_ROOT/dist"

echo "[build] Compiling unified pure-Rust workspace inside $IMAGE_TAG..."
docker run --rm \
    -u "$(id -u):$(id -g)" \
    -v "$REPO_ROOT:/work" \
    "${DOCKER_CACHE_ARGS[@]}" \
    -w /work \
    -e HOME=/tmp \
    -e TZ=UTC \
    -e LC_ALL=C.UTF-8 \
    -e SOURCE_DATE_EPOCH=1700000000 \
    -e CARGO_INCREMENTAL=0 \
    -e CARGO_HOME=/cargo-cache \
    "$IMAGE_TAG" \
    bash -c '
        set -euo pipefail
        mkdir -p dist

        COMMON_REMAP="--remap-path-prefix=/work=/subzero --remap-path-prefix=/cargo-cache=/cargo -C debuginfo=0"

        echo "  [1/4] Building zero-import WASM engine (wasm32-unknown-unknown)..."
        # WHY explicit CC/AR for wasm32: `rust-musl-cross` sets TARGET_CC to musl-gcc for x86_64;
        # `secp256k1-sys` C sources must use `clang --target=wasm32-unknown-unknown` + `llvm-ar`
        # so `rust-lld -flavor wasm` links real WASM object files instead of x86_64 ELF objects.
        CC_wasm32_unknown_unknown=clang \
        AR_wasm32_unknown_unknown=llvm-ar \
        CFLAGS_wasm32_unknown_unknown="-ffile-prefix-map=/work=/subzero -ffile-prefix-map=/cargo-cache=/cargo -g0" \
        CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
        RUSTFLAGS="$COMMON_REMAP" \
        cargo build --locked --release --target wasm32-unknown-unknown -p subzero-wasm

        echo "  [2/4] Bundling CSP-hash-pinned single-file HTML artifacts..."
        python3 scripts/bundle_html.py \
            --wasm target/wasm32-unknown-unknown/release/subzero_wasm.wasm \
            --kiosk-template web/subzero-keyosk.template.html \
            --decrypt-template web/decrypt.template.html \
            --out-dir dist \
            --sync-assets-decrypt assets/decrypt.html

        echo "  [3/4] Building static bare-metal Linux TUI (x86_64-unknown-linux-musl)..."
        CFLAGS="-ffile-prefix-map=/work=/subzero -ffile-prefix-map=/cargo-cache=/cargo -g0" \
        RUSTFLAGS="$COMMON_REMAP -C target-feature=+crt-static -C link-arg=-Wl,--build-id=none" \
        cargo build --locked --release --target x86_64-unknown-linux-musl -p subzero-tui

        cp target/x86_64-unknown-linux-musl/release/subzero dist/subzero-x86_64-musl
        chmod 0755 dist/subzero-x86_64-musl
        chmod 0644 dist/subzero-keyosk.html dist/decrypt.html assets/decrypt.html

        echo "  [4/4] Generating deterministic dist/SHA256SUMS..."
        (
            cd dist
            sha256sum subzero-x86_64-musl subzero-keyosk.html decrypt.html > SHA256SUMS
            chmod 0644 SHA256SUMS
        )
    '

echo "[verify] Running native static binary KAT self-test..."
"$REPO_ROOT/dist/subzero-x86_64-musl" --self-test

echo "[verify] Freshly built artifact digests ($REPO_ROOT/dist/SHA256SUMS):"
cat "$REPO_ROOT/dist/SHA256SUMS"

if [[ "$MODE" == "update" ]]; then
    cp "$REPO_ROOT/dist/SHA256SUMS" "$REPO_ROOT/SHA256SUMS"
    chmod 0644 "$REPO_ROOT/SHA256SUMS"
    echo "[manifest] Updated $REPO_ROOT/SHA256SUMS."
elif [[ "$MODE" == "verify" ]]; then
    if [[ ! -f "$REPO_ROOT/SHA256SUMS" ]]; then
        echo "FATAL: $REPO_ROOT/SHA256SUMS not found for --verify." >&2
        exit 1
    fi
    diff -u "$REPO_ROOT/SHA256SUMS" "$REPO_ROOT/dist/SHA256SUMS"
    (cd "$REPO_ROOT/dist" && sha256sum -c "$REPO_ROOT/SHA256SUMS")
    echo "[verify] REPRODUCIBLE BUILD VERIFIED: 100% bit-for-bit match against committed SHA256SUMS."
else
    if [[ -f "$REPO_ROOT/SHA256SUMS" ]]; then
        diff -u "$REPO_ROOT/SHA256SUMS" "$REPO_ROOT/dist/SHA256SUMS"
        (cd "$REPO_ROOT/dist" && sha256sum -c "$REPO_ROOT/SHA256SUMS")
        echo "[verify] REPRODUCIBLE BUILD VERIFIED: 100% bit-for-bit match against committed SHA256SUMS."
    else
        cp "$REPO_ROOT/dist/SHA256SUMS" "$REPO_ROOT/SHA256SUMS"
        chmod 0644 "$REPO_ROOT/SHA256SUMS"
        echo "[manifest] Created initial $REPO_ROOT/SHA256SUMS."
    fi
fi
