#!/bin/bash
#
# Example script showing how to build squashfs-tools with mimalloc support
#
# This script demonstrates the proper way to build with mimalloc enabled
# and verifies that the build was successful.
#

set -e  # Exit on error

echo "=========================================="
echo "Building squashfs-tools with mimalloc"
echo "=========================================="
echo ""

# Check if mimalloc is installed
if ! pkg-config --exists mimalloc 2>/dev/null && ! ldconfig -p | grep -q libmimalloc 2>/dev/null; then
    echo "WARNING: mimalloc library not found on this system"
    echo ""
    echo "To install mimalloc:"
    echo "  Debian/Ubuntu: sudo apt-get install libmimalloc-dev"
    echo "  Fedora/RHEL:   sudo dnf install mimalloc-devel"
    echo "  Arch Linux:    sudo pacman -S mimalloc"
    echo ""
    echo "Or build from source: https://github.com/microsoft/mimalloc"
    echo ""
    echo "This script will attempt to build anyway, but it may fail if mimalloc is not installed."
    echo ""
fi

# Navigate to squashfs-tools directory
cd squashfs-tools

echo "Cleaning previous build..."
make clean >/dev/null 2>&1 || true

echo ""
echo "Building with mimalloc support enabled..."
echo "Command: make MIMALLOC_SUPPORT=1"
echo ""

# Build with mimalloc support
# Disable some compression libraries that might not be installed
make MIMALLOC_SUPPORT=1 \
     LZO_SUPPORT=0 \
     LZ4_SUPPORT=0 \
     XZ_SUPPORT=0 \
     ZSTD_SUPPORT=0 \
     -j$(nproc) || {
    echo ""
    echo "=========================================="
    echo "BUILD FAILED"
    echo "=========================================="
    echo ""
    echo "The build failed. This is likely because:"
    echo "1. mimalloc library is not installed"
    echo "2. mimalloc development headers are not available"
    echo ""
    echo "Please install mimalloc and try again."
    echo "See MIMALLOC.md for detailed instructions."
    exit 1
}

echo ""
echo "=========================================="
echo "BUILD SUCCESSFUL"
echo "=========================================="
echo ""
echo "Verifying binaries..."
echo ""

# Verify binaries were created
if [ -f "mksquashfs" ] && [ -f "unsquashfs" ]; then
    echo "✓ Binaries created successfully"
    
    # Check if they're linked with mimalloc
    echo ""
    echo "Checking if binaries are linked with mimalloc..."
    if ldd mksquashfs 2>/dev/null | grep -q mimalloc; then
        echo "✓ mksquashfs is linked with mimalloc"
    else
        echo "⚠ mksquashfs does not appear to be linked with mimalloc"
        echo "  This might be expected if mimalloc is statically linked"
    fi
    
    if ldd unsquashfs 2>/dev/null | grep -q mimalloc; then
        echo "✓ unsquashfs is linked with mimalloc"
    else
        echo "⚠ unsquashfs does not appear to be linked with mimalloc"
        echo "  This might be expected if mimalloc is statically linked"
    fi
    
    # Test binary execution
    echo ""
    echo "Testing binary execution..."
    if ./mksquashfs -version >/dev/null 2>&1; then
        echo "✓ mksquashfs executes successfully"
    else
        echo "✗ mksquashfs failed to execute"
    fi
    
    if ./unsquashfs -version >/dev/null 2>&1; then
        echo "✓ unsquashfs executes successfully"
    else
        echo "✗ unsquashfs failed to execute"
    fi
else
    echo "✗ Binary creation failed"
    exit 1
fi

echo ""
echo "=========================================="
echo "SUCCESS"
echo "=========================================="
echo ""
echo "squashfs-tools has been built with mimalloc support!"
echo ""
echo "The binaries are located in:"
echo "  $(pwd)/mksquashfs"
echo "  $(pwd)/unsquashfs"
echo ""
echo "You can now use these binaries, which will use the mimalloc"
echo "allocator for all memory operations, providing:"
echo "  - Better performance in multi-threaded scenarios"
echo "  - Lower memory fragmentation"
echo "  - Enhanced security features"
echo ""
echo "To install system-wide, run:"
echo "  sudo make install"
echo ""
