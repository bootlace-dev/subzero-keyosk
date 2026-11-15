#!/usr/bin/env bash
# ==============================================================================
# SubZero v2.0 - Sovereign Dual-Signing, GitHub Release & Issue Alignment Script
# (`scripts/sign_and_push_v2.sh`)
# ==============================================================================
#
# WHY THIS SCRIPT ENFORCES STRICT IDENTITY, BRANCH & FD-ISOLATED SIGNING:
# 1. Clean Branch & Working-Tree Guard:
#    Refuses to run unless the checked-out Git branch is `main` and all tracked
#    source files (outside `SHA256SUMS.asc` and `SHA256SUMS.pk1`) are cleanly
#    committed, preventing accidental pushes of uncommitted edits or stale branches.
# 2. Account Isolation Guard:
#    Refuses to run any `gh` or `git push` command unless the active GitHub CLI
#    identity (`gh api user --jq .login`) is strictly `bootlace-dev` and local
#    `git config user.email` is `bootlace-dev@users.noreply.github.com`.
# 3. Atomic Temp-File Signing & Pinned-Key Verification (`--sec-fd 3`):
#    When signing `SHA256SUMS.pk1`, secret key material is passed exclusively
#    over file descriptor 3 (`3<<<"$PK1_SEC"`) into a temporary file and verified
#    against `./bootlace-dev-pipek1.pub` before replacing `SHA256SUMS.pk1`.
#    OpenPGP `SHA256SUMS.asc` is verified inside an isolated temporary `GNUPGHOME`
#    against `./bootlace-dev-release.asc` (`F18173E554644BB59018AE50F6E96FADCA2E8E0F`).
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PGP_KEY_ID="F18173E554644BB59018AE50F6E96FADCA2E8E0F"
PIPEK1_NPUB="$(awk '/^Npub:/ {print $2}' bootlace-dev-pipek1.pub)"
TAG="v2.0.0-testnet4"

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$CURRENT_BRANCH" != "main" ]]; then
    echo "FATAL: Current branch is '$CURRENT_BRANCH' (expected 'main')." >&2
    exit 1
fi

DIRTY_TRACKED="$(git status --porcelain --untracked-files=no | grep -vE '^.. SHA256SUMS(\.asc|\.pk1)?$' || true)"
if [[ -n "$DIRTY_TRACKED" ]]; then
    echo "FATAL: Uncommitted tracked changes detected outside SHA256SUMS signatures:" >&2
    echo "$DIRTY_TRACKED" >&2
    exit 1
fi

verify_pgp_isolated() {
    local sig_file="$1"
    local target_file="$2"
    local tmp_gpg
    tmp_gpg="$(mktemp -d)"
    chmod 0700 "$tmp_gpg"
    if GNUPGHOME="$tmp_gpg" gpg --batch --quiet --import bootlace-dev-release.asc >/dev/null 2>&1 && \
       GNUPGHOME="$tmp_gpg" gpg --batch --status-fd 1 --verify "$sig_file" "$target_file" 2>/dev/null | grep -q "VALIDSIG $PGP_KEY_ID"; then
        rm -rf "$tmp_gpg"
        return 0
    fi
    rm -rf "$tmp_gpg"
    return 1
}

echo "[1/7] Verifying reproducible artifact hashes and KAT self-test..."
./dist/subzero-x86_64-musl --self-test
diff -u SHA256SUMS dist/SHA256SUMS
(cd dist && sha256sum -c ../SHA256SUMS)

echo "[2/7] Verifying or creating pipe-k1 detached signature (SHA256SUMS.pk1)..."
if [[ -f SHA256SUMS.pk1 ]] && command -v pipe-k1 >/dev/null 2>&1 && pipe-k1 verify --sig SHA256SUMS.pk1 --pub "$PIPEK1_NPUB" < SHA256SUMS >/dev/null 2>&1; then
    echo "  [OK] Existing SHA256SUMS.pk1 verified against $PIPEK1_NPUB."
else
    TMP_PK1="$(mktemp)"
    read -r -s -p "Enter operational pipe-k1 secret (nsec1... or 64-char hex for $PIPEK1_NPUB): " PK1_SEC
    echo ""
    if ! pipe-k1 sign -a --sec-fd 3 < SHA256SUMS 3<<<"$PK1_SEC" > "$TMP_PK1"; then
        unset PK1_SEC
        rm -f "$TMP_PK1"
        echo "FATAL: pipe-k1 signing failed." >&2
        exit 1
    fi
    unset PK1_SEC
    if ! pipe-k1 verify --sig "$TMP_PK1" --pub "$PIPEK1_NPUB" < SHA256SUMS; then
        rm -f "$TMP_PK1"
        echo "FATAL: Generated signature did not match pinned key $PIPEK1_NPUB." >&2
        exit 1
    fi
    chmod 0644 "$TMP_PK1"
    mv "$TMP_PK1" SHA256SUMS.pk1
fi
cp SHA256SUMS.pk1 dist/SHA256SUMS.pk1

echo "[3/7] Signing SHA256SUMS.asc with OpenPGP key $PGP_KEY_ID..."
if [[ -f SHA256SUMS.asc ]] && verify_pgp_isolated SHA256SUMS.asc SHA256SUMS; then
    echo "  [OK] Existing SHA256SUMS.asc verified against bootlace-dev-release.asc."
else
    TMP_ASC="$(mktemp)"
    rm -f "$TMP_ASC"
    gpg --armor --detach-sign --local-user "$PGP_KEY_ID" --output "$TMP_ASC" SHA256SUMS
    if ! verify_pgp_isolated "$TMP_ASC" SHA256SUMS; then
        rm -f "$TMP_ASC"
        echo "FATAL: SHA256SUMS.asc failed isolated verification against bootlace-dev-release.asc." >&2
        exit 1
    fi
    chmod 0644 "$TMP_ASC"
    mv "$TMP_ASC" SHA256SUMS.asc
fi
cp SHA256SUMS.asc dist/SHA256SUMS.asc

echo "[4/7] Committing dual release signatures on clean main branch..."
GIT_EMAIL="$(git config user.email || true)"
if [[ "$GIT_EMAIL" != "bootlace-dev@users.noreply.github.com" ]]; then
    echo "FATAL: git user.email is '$GIT_EMAIL' (expected bootlace-dev@users.noreply.github.com)" >&2
    exit 1
fi
git add SHA256SUMS SHA256SUMS.pk1 SHA256SUMS.asc
if ! git diff --cached --quiet; then
    git commit -m "chore(release): attach dual PGP and pipe-k1 signatures for $TAG"
fi

echo "[5/7] Checking isolated GitHub CLI identity (must be bootlace-dev)..."
PREV_GH="$(gh api user --jq .login 2>/dev/null || true)"
restore_gh_account() {
    if [[ -n "$PREV_GH" && "$PREV_GH" != "bootlace-dev" ]]; then
        gh auth switch --user "$PREV_GH" >/dev/null 2>&1 || true
    fi
}
trap restore_gh_account EXIT

gh auth switch --user bootlace-dev >/dev/null 2>&1 || true
ACTIVE_GH="$(gh api user --jq .login)"
if [[ "$ACTIVE_GH" != "bootlace-dev" ]]; then
    echo "FATAL: Active gh account is '$ACTIVE_GH' - refusing to push outside bootlace-dev!" >&2
    exit 1
fi

echo "[6/7] Publishing clean main history, $TAG release assets, and repository metadata..."
git push --force origin main

# Remove pre-v2 prototype branches, releases, and tags so deprecated commits/builds are unreachable
for old_branch in feat/appliance-milestones feat/import-offline-seed feat/rust-port master; do
    git push origin ":refs/heads/$old_branch" 2>/dev/null || true
done

for old_tag in v0.3.0 v0.4.0-testnet4; do
    gh release delete "$old_tag" --repo bootlace-dev/subzero-keyosk --yes --cleanup-tag 2>/dev/null || true
    git push origin ":refs/tags/$old_tag" 2>/dev/null || true
done

git tag -f "$TAG"
git push --force origin "$TAG"

if gh release view "$TAG" --repo bootlace-dev/subzero-keyosk >/dev/null 2>&1; then
    gh release delete "$TAG" --repo bootlace-dev/subzero-keyosk --yes
fi

gh release create "$TAG" \
    dist/subzero-x86_64-musl \
    dist/subzero-keyosk.html \
    dist/decrypt.html \
    dist/SHA256SUMS \
    dist/SHA256SUMS.asc \
    dist/SHA256SUMS.pk1 \
    --repo bootlace-dev/subzero-keyosk \
    --title "SubZero Keyosk v2.0.0-testnet4 (Unified Pure-Rust Core + Reproducible Builds)" \
    --notes "Clean-slate v2.0 architecture unifying Bare-Metal Linux (\`subzero-x86_64-musl\`) and Standalone Zero-Import WASM HTML (\`subzero-keyosk.html\` & \`decrypt.html\`) onto \`crates/subzero-core\` with bit-for-bit reproducible Docker builds, Cooperative Two-Tier Entropy, 10 funded Testnet4 rehearsal presets, cryptographic PSBT self-change verification, SIV-committed \`subzero-vault-v2\` encryption, and native \`pipe-k1\` release signing."

gh repo edit bootlace-dev/subzero-keyosk \
    --description "Airgapped Zero-OS-RNG Bitcoin Testnet4 Cold Vault, Verified PSBT BBQr Signer & BIP-85 Estate Tool (Pure Rust -> Static musl + Single-File WASM HTML)"

echo "[7/7] Closing resolved pre-v2 GitHub issues (#4, #5, #6)..."
for num in 4 5 6; do
    gh issue close "$num" \
        --repo bootlace-dev/subzero-keyosk \
        --comment "Resolved in $TAG via unified pure-Rust \`crates/subzero-core\` (adaptive integral-image QR glare thresholding, canonical BIP-380 descriptors, real Coinkite BBQr, and bit-for-bit reproducible builds)." 2>/dev/null || true
done

echo "DONE: bootlace-dev/subzero-keyosk $TAG published and verified."
