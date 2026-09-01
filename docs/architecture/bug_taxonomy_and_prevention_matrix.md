# The Four Bug Taxonomies & Systematic Prevention Matrix

> **Target:** SubZero Keyosk & Sovereign Cryptographic Systems  
> **Author Frame:** Principal Systems & Security Architect  
> **Scope:** Elimination of All Adjacent and "Rhyming" Software, Shell, Memory, and Hardware Defects

---

## 1. Executive Summary: The Anatomy of "Rhyming" Bugs

Software bugs do not occur at random; they cluster in specific **structural fault lines** where different layers of abstraction meet (e.g., Shell $\leftrightarrow$ Kernel, TypeScript $\leftrightarrow$ V8 Heap, Specification $\leftrightarrow$ Binary Artifact, Host $\leftrightarrow$ Target Hardware).

To prevent these classes of bugs from ever recurring, we categorize them into **Four Distinct Taxonomies**, map every "rhyming" variant, and establish automated fail-closed defenses for each.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          THE FOUR BUG TAXONOMIES                                │
├───────────────────────────────────────┬─────────────────────────────────────────┤
│ 1. ENVIRONMENT & VARIABLE DRIFT       │ 2. CONTRACT VS. ARTIFACT DIVERGENCE     │
│    (Shell / Subshell / Unbound State) │    (Documentation vs. Binary Media)     │
├───────────────────────────────────────┼─────────────────────────────────────────┤
│ 3. ALGORITHMIC & MEMORY HYGIENE       │ 4. HARDWARE & SUBSYSTEM COERCION        │
│    (Truncation / Type Leaks / Wiping) │    (KMS / VFAT / ACPI / UEFI / eMMC)    │
└───────────────────────────────────────┴─────────────────────────────────────────┘
```

---

## 2. Deep-Dive Taxonomy Breakdown & Systematic Preventions

### Taxonomy 1: Environment & Variable Drift (The Shell Glue Trap)
* **The Root Mechanism**: Shell scripts evaluate unassigned or misspelled variables as empty strings `""` or fail when `set -u` is evaluated in trap handlers, leading to silent wrong paths or abrupt crashes.
* **The "Rhyming" Variants**:
  1. *Subshell Variable Bleed*: Variables exported in `(cd foo && VAR=x)` lost when returning to parent shell.
  2. *Path Tokenization on Spaces*: `cp $SRC $DST` splitting if directory contains spaces.
  3. *Sudo Environment Scrubbing*: `sudo` stripping `$PATH` or changing `$HOME` to `/root`.
  4. *Trap Handler Unbound Vars*: Trap executing during early initialization before variables are defined.
* **Systematic Prevention**:
  * **Strict Mode Header**: Every script MUST start with `set -euo pipefail`.
  * **Default Parameter Expansion**: Always use `${VAR:-}` for optional or trap-scoped variables.
  * **Script-Level Pre-Initialization**: Define all script variables (`LOOP_DEV=""`, `MOUNT_DIR=""`) at line 1.
  * **Automated Vitest AST Scan**: `tests/scripts_audit.test.ts` statically asserts strict mode and blocks unbound variable patterns across all `.sh` files.

---

### Taxonomy 2: Contract vs. Artifact Divergence (The Manifest Gap)
* **The Root Mechanism**: The specification or UI declares that an artifact, file, or feature exists, but the automated build script fails to package it or packages an empty dummy file.
* **The "Rhyming" Variants**:
  1. *Missing Manifests*: Formatting an estate partition without embedding `SHA256SUMS`.
  2. *Chroot Trigger Blindness*: `apk add` triggers expecting a real block device on `/`.
  3. *Dynamic Linking Breakage*: Packaging a binary like `node` into squashfs while missing a shared library dependency (`libc`, `libgcc_s.so`).
  4. *Partition Boundary Overrun*: GPT partition table specifying 512MB, but partition slices colliding.
* **Systematic Prevention**:
  * **Step 11 Fail-Closed Verification Gate**: Every disk builder MUST mount and verify raw partition images (`mdir -i ...`) before concluding.
  * **Dynamic Shared Library Check (`ldd`)**: Test inside chroot: `chroot "${ROOTFS_DIR}" node -v` to ensure runtime execution before packaging.
  * **Checksum Self-Assertion**: Run `sha256sum -c SHA256SUMS` on partition files before completing build.

---

### Taxonomy 3: Algorithmic & Memory Hygiene (The "Happy-Path" Test Illusion)
* **The Root Mechanism**: Automated unit tests verify binary pass/fail status (e.g. `valid === false`), but fail to test **quality of result**, typo-recovery ranking, or runtime memory mutations.
* **The "Rhyming" Variants**:
  1. *Candidate Truncation*: Slicing the first 16 alphabetical words (`candidates.slice(0, 16)`) instead of Levenshtein-ranking by similarity to what was typed.
  2. *Type-Mismatch Zeroization*: Calling `.fill(0)` on a primitive string instead of an Array/Buffer (`TypeError`).
  3. *Dangling Heap References*: Overwriting an object pointer while the underlying binary seed buffer remains unzeroized in V8 memory.
  4. *Frame Buffer Stride Padding Overrun*: Writing 3 bytes on 16bpp (RGB565) displays or missing alpha byte zeroization.
* **Systematic Prevention**:
  * **Adversarial Typo Mutation Tests**: Unit tests MUST inject deliberate 1-char and 2-char typos and assert that the intended word is returned at **Rank 1**.
  * **Explicit Type-Aware Zeroization**: Strict primitive buffer overwrites (`rootSeed.fill(0)` + direct hardware `directWipe(0x00)`).
  * **SIGINT Event Interception**: Attaching memory wipe routines directly to process exit and signal listeners.

---

### Taxonomy 4: Hardware & Subsystem Coercion (The OS / Kernel Boundary)
* **The Root Mechanism**: Kernel drivers (VFAT, SimpleDRM, ACPI) enforce strict hardware constraints that fail when assumed to behave like standard POSIX filesystems.
* **The "Rhyming" Variants**:
  1. *Dirty Bit Read-Only Remount (`EROFS`)*: Linux VFAT driver defaulting to `ro` when a filesystem was not cleanly unmounted.
  2. *Block Device Read-Only Flags*: Chromebook internal SD readers initializing block devices in read-only mode until cleared by `blockdev --setrw`.
  3. *ACPI Suspend Lockouts on Laptop Reboot*: Scheduled reboots failing because laptop lid is closed.
  4. *Framebuffer DRM/KMS Fallbacks*: `fbcon` failing to bind on UEFI machines without `video=efifb` or `simpledrm`.
* **Systematic Prevention**:
  * **Defense-in-Depth Mount Pipeline**:
    `blockdev --setrw` $\to$ `fsck.vfat -a` $\to$ `mount -t vfat -o rw,sync,umask=000,errors=continue` $\to$ `mount -o remount,rw`.
  * **Headless QEMU Emulation Verification**: Testing across split OVMF UEFI, IDE buses, and 16bpp/32bpp virtual displays.
  * **Forced Kernel Cutoff**: Using `exec /sbin/poweroff -f` to bypass ACPI userland suspend locks.

---

## 3. The Systematic Prevention Matrix

| Bug Class | Real-World Failure Example | Systematic Automated Cure |
| :--- | :--- | :--- |
| **Unbound Var** | `${PROJECT_DIR}` evaluated as `""` | `set -euo pipefail` + `tests/scripts_audit.test.ts` |
| **Trap Crash** | `LOOP_DEV: unbound variable` on exit | Pre-initialize `LOOP_DEV=""` + `${LOOP_DEV:-}` expansion |
| **Chroot Trigger** | `grub-probe` error during `apk add` | Stub binary: `ln -sf /bin/true /usr/sbin/grub-probe` |
| **Missing Manifest** | `SHA256SUMS` missing on SD card | Step 11 Fail-Closed image assertion (`mdir`) |
| **Typo Truncation** | Candidate #72 `mix` omitted for `fix` | Levenshtein edit-distance ranking + `tests/seedfix.test.ts` |
| **Zeroize Crash** | `h.words.fill is not a function` | String buffer overwrite + `rootSeed.fill(0)` |
| **Hardware EROFS** | SD write fails: read-only filesystem | `blockdev --setrw` + `fsck.vfat -a` + `-o rw,sync,umask=000` |
| **16bpp Stride** | Display distortion on legacy VGA | Little-endian RGB565 packing in `drawPixel()` |

---

## 4. The Golden Rule of Agentic Architecture
> **"Never trust an unconstrained LLM happy-path. Force every abstraction to fail closed under strict compilers, static syntax scanners, adversarial input mutations, and raw binary assertions."**
