# Security Policy

## Reporting a Vulnerability

Because SubZero Keyosk is designed for cold storage of Bitcoin assets, all security reports, cryptographic flaws, and edge-case anomalies are treated with the highest severity.

To privately submit a security report without public disclosure:

1. Navigate to the **Security** tab of this GitHub repository.
2. Select **Advisories** in the left sidebar.
3. Click **Report a vulnerability**.
4. Provide a clear description of the flaw, reproduction steps or mathematical proofs, and the affected modules (`src/crypto.ts`, `src/fb_testnet4.ts`, `src/framebuffer.ts`, `scripts/build_alpine_kiosk.sh`, or `scripts/build_rpi_kiosk.sh`).

All valid vulnerability disclosures are triaged in an isolated sandbox environment. Please do not open public GitHub Issues for critical cryptographic or memory leakage vulnerabilities.
