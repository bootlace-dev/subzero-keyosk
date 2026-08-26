#!/bin/bash
set -e

echo "==========================================="
echo "       Building SubZero Amnesic OS         "
echo "==========================================="

# Apply our custom configuration to Buildroot
cp /build/subzero_defconfig /build/buildroot/.config

# Compile Buildroot
cd /build/buildroot
make olddefconfig
make

# Assemble output using genimage
echo "Assembling partition images into subzero.img..."
mkdir -p /build/output
cp /build/buildroot/output/images/subzero.img /build/output/subzero.img

echo "SubZero bootable image compiled successfully: /build/output/subzero.img"
