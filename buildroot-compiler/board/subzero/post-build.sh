#!/bin/sh
set -e

# Target root directory is passed as $1 by Buildroot
TARGET_DIR="$1"

echo "==========================================="
echo "     Running SubZero Post-Build Script     "
echo "==========================================="

# Create target application directory
mkdir -p "${TARGET_DIR}/opt/subzero"

# Copy the compiled HTML kiosk bundle to target filesystem
if [ -f "/build/subzero_signer_app.html" ]; then
    cp "/build/subzero_signer_app.html" "${TARGET_DIR}/opt/subzero/index.html"
else
    echo "Warning: subzero_signer_app.html not found, using generic placeholder."
    echo "<h1>SubZero Keygen Placeholder</h1>" > "${TARGET_DIR}/opt/subzero/index.html"
fi

# Create autostart init script for Cog browser kiosk on framebuffer
mkdir -p "${TARGET_DIR}/etc/init.d"
cat << 'EOF' > "${TARGET_DIR}/etc/init.d/S99kiosk"
#!/bin/sh
# Cog Browser Framebuffer Kiosk Autostart

case "$1" in
  start)
    echo "Starting SubZero Keygen Kiosk..."
    # Disable JIT compiler for heap side-channel mitigation
    export JSC_useJIT=0
    
    # Run Cog directly on the graphics framebuffer (KMS/DRM platform)
    cog --platform=drm file:///opt/subzero/index.html >/dev/null 2>&1 &
    ;;
  stop)
    killall cog
    ;;
  restart)
    $0 stop
    sleep 1
    $0 start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
esac
exit 0
EOF

chmod +x "${TARGET_DIR}/etc/init.d/S99kiosk"

# Disable network interfaces from starting automatically
if [ -f "${TARGET_DIR}/etc/network/interfaces" ]; then
    echo "# Network interfaces disabled for airgap isolation" > "${TARGET_DIR}/etc/network/interfaces"
fi

# Ensure read-only fstab mounts for amnesic execution
if [ -f "${TARGET_DIR}/etc/fstab" ]; then
    cat << 'EOF' > "${TARGET_DIR}/etc/fstab"
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
/dev/root       /               ext4    ro,noatime      0       1
tmpfs           /tmp            tmpfs   nosuid,nodev    0       0
tmpfs           /var            tmpfs   nosuid,nodev    0       0
tmpfs           /dev/shm        tmpfs   nosuid,nodev    0       0
EOF
fi

echo "Post-Build Configuration Completed Successfully."
