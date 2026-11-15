#!/usr/bin/env python3
"""Deterministic Single-File HTML + Inline WASM Bundler for SubZero v2.0.

WHY THIS BUNDLER EXISTS (ZERO NPM SUPPLY CHAIN + REPRODUCIBLE CSP HASH PINNING):
1. Legacy SubZero relied on a 245-package `node_modules/` Vite/TypeScript tree that drifted
   cryptographically from the Rust appliance and pulled `Buffer.from()` polyfill bugs.
2. In v2.0, `subzero-wasm` compiles `crates/subzero-core` directly to a zero-import
   `wasm32-unknown-unknown` binary. This pure-Python stdlib script Base64-encodes the stripped
   `.wasm` binary into `web/subzero-keyosk.template.html` and `web/decrypt.template.html`, then
   computes exact W3C CSP Level 3 `sha256-...` digests over the exact `<style>` and `<script>`
   tag bodies so neither `'unsafe-inline'` nor external files are ever required.
3. Zero wall-clock timestamps, git dirty flags, or host filesystem paths are written into the
   generated HTML, guaranteeing bit-for-bit identical `SHA256SUMS` across clean-room builds.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import sys
from pathlib import Path


STYLE_RE = re.compile(r"<style id=\"sz-style\">(.*?)</style>", re.DOTALL)
SCRIPT_RE = re.compile(r"<script id=\"sz-script\">(.*?)</script>", re.DOTALL)


def csp_sha256(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def render_single_file(template_path: Path, wasm_b64: str, out_path: Path) -> str:
    raw = template_path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    if "{{WASM_BASE64}}" not in raw:
        raise RuntimeError(f"Missing {{{{WASM_BASE64}}}} placeholder in {template_path}")

    populated = raw.replace("{{WASM_BASE64}}", wasm_b64)

    style_match = STYLE_RE.search(populated)
    script_match = SCRIPT_RE.search(populated)
    if not style_match or not script_match:
        raise RuntimeError(
            f"Template {template_path} must contain exactly one <style id=\"sz-style\"> and <script id=\"sz-script\">."
        )

    style_hash = csp_sha256(style_match.group(1))
    script_hash = csp_sha256(script_match.group(1))

    if "{{CSP_STYLE_HASH}}" not in populated or "{{CSP_SCRIPT_HASH}}" not in populated:
        raise RuntimeError(f"Missing CSP hash placeholders in {template_path}")

    final_html = (
        populated.replace("{{CSP_STYLE_HASH}}", style_hash)
        .replace("{{CSP_SCRIPT_HASH}}", script_hash)
    )

    # Guardrail: forbid inline event handlers (`onclick=`, `onerror=`, `style=`) in HTML markup tags
    markup_only = SCRIPT_RE.sub("", STYLE_RE.sub("", final_html))
    if re.search(r"<[^>]+\b(?:on[a-z]+|style)\s*=", markup_only, re.IGNORECASE):
        raise RuntimeError(
            f"Forbidden inline DOM event handler or style= attribute found in HTML markup of {template_path}"
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(final_html.encode("utf-8"))
    file_sha = hashlib.sha256(final_html.encode("utf-8")).hexdigest()
    return file_sha


def main() -> int:
    parser = argparse.ArgumentParser(description="Bundle SubZero WASM into standalone CSP-locked HTML files.")
    parser.add_argument("--wasm", required=True, type=Path, help="Path to compiled subzero_wasm.wasm")
    parser.add_argument("--kiosk-template", required=True, type=Path, help="Path to subzero-keyosk.template.html")
    parser.add_argument("--decrypt-template", required=True, type=Path, help="Path to decrypt.template.html")
    parser.add_argument("--out-dir", required=True, type=Path, help="Output directory (e.g. dist/)")
    parser.add_argument(
        "--sync-assets-decrypt",
        type=Path,
        default=None,
        help="Optional path (e.g. assets/decrypt.html) to keep embedded bare-metal decrypt.html in lockstep.",
    )
    args = parser.parse_args()

    wasm_bytes = args.wasm.read_bytes()
    if len(wasm_bytes) < 1024 or wasm_bytes[:4] != b"\x00asm":
        print(f"Error: {args.wasm} is not a valid WebAssembly binary.", file=sys.stderr)
        return 1

    wasm_b64 = base64.b64encode(wasm_bytes).decode("ascii")

    decrypt_out = args.out_dir / "decrypt.html"
    kiosk_out = args.out_dir / "subzero-keyosk.html"

    dec_sha = render_single_file(args.decrypt_template, wasm_b64, decrypt_out)
    if args.sync_assets_decrypt is not None:
        args.sync_assets_decrypt.parent.mkdir(parents=True, exist_ok=True)
        args.sync_assets_decrypt.write_bytes(decrypt_out.read_bytes())
    kiosk_sha = render_single_file(args.kiosk_template, wasm_b64, kiosk_out)

    print(f"{dec_sha}  {decrypt_out}")
    print(f"{kiosk_sha}  {kiosk_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
