# ===========================================================================
#  SubZero Keyosk — Master Multi-Architecture Build Driver
#  Provides standard Bitcoin Core-style targets with hermetic container safety.
# ===========================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help all test preflight build-bundles mainnet-all testnet4-all \
        mainnet-pc mainnet-rpi testnet4-pc testnet4-rpi qemu-pc qemu-testnet4 clean

help:
	@echo "======================================================================"
	@echo "  SUBZERO KEYOSK: Master Multi-Architecture Build System"
	@echo "======================================================================"
	@echo "  make test             : Run full Vitest suite + 3-way multi-arch preflight"
	@echo "  make testnet4-all     : Compile both PC (x86_64) and RPi Testnet4 images"
	@echo "  make testnet4-pc      : Compile dist/subzero-testnet4-pc.img"
	@echo "  make testnet4-rpi     : Compile dist/subzero-testnet4-rpi.img"
	@echo "  make mainnet-all      : Compile both PC (x86_64) and RPi Mainnet images"
	@echo "  make mainnet-pc       : Compile dist/subzero-alpine.img (PC Mainnet)"
	@echo "  make mainnet-rpi      : Compile dist/subzero-rpi.img (RPi Mainnet)"
	@echo "  make qemu-testnet4    : Boot Testnet4 PC image in local QEMU UEFI"
	@echo "  make qemu-pc          : Boot Mainnet PC image in local QEMU UEFI"
	@echo "  make clean            : Wipe dist/ and temporary build caches"
	@echo "======================================================================"

# --- Verification & Pre-Flight ---
test:
	npm test
	./scripts/test_preflight_matrix.sh

preflight:
	./scripts/test_preflight_matrix.sh

fuzz-entropy:
	./scripts/test_random_differential.sh 5

# --- Bundling ---
build-bundles:
	npm run build:all

# --- Testnet4 Image Targets ---
testnet4-all: testnet4-pc testnet4-rpi

testnet4-pc: build-bundles
	@echo ">>> Compiling Testnet4 PC UEFI Image (x86_64)..."
	./scripts/build_alpine_containerized.sh tui_testnet4.cjs subzero-testnet4-pc.img

testnet4-rpi: build-bundles
	@echo ">>> Compiling Testnet4 Raspberry Pi Image (armv7 / arm64)..."
	./scripts/build_rpi_containerized.sh tui_testnet4.cjs subzero-testnet4-rpi.img

# --- Mainnet Image Targets ---
mainnet-all: mainnet-pc mainnet-rpi

mainnet-pc: build-bundles
	@echo ">>> Compiling Mainnet PC UEFI Image (x86_64)..."
	./scripts/build_alpine_containerized.sh tui.cjs subzero-alpine.img

mainnet-rpi: build-bundles
	@echo ">>> Compiling Mainnet Raspberry Pi Image (armv7 / arm64)..."
	./scripts/build_rpi_containerized.sh tui.cjs subzero-rpi.img

# --- Virtual Machine Emulation ---
qemu-testnet4:
	./scripts/run_qemu.sh dist/subzero-testnet4-pc.img

qemu-pc:
	./scripts/run_qemu.sh dist/subzero-alpine.img

# --- Clean ---
clean:
	rm -rf dist/*.img dist/*.cjs
