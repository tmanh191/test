#!/bin/bash
# Setup script for detector.py - Check and install required dependencies

set -e

echo "=== Detector Setup Script ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (sudo ./setup.sh)"
    exit 1
fi

echo "✅ Running as root"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo "❌ Cannot detect OS"
    exit 1
fi

echo "📦 Detected OS: $OS $VER"
echo ""

# Check kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

echo "🐧 Kernel version: $(uname -r)"

if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 8 ]); then
    echo "⚠️  Kernel < 5.8: Ring buffer not available, will use perf buffer"
else
    echo "✅ Kernel >= 5.8: Ring buffer available"
fi
echo ""

# Check Python 3
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo "✅ Python 3: $PYTHON_VERSION"
else
    echo "❌ Python 3 not found"
    echo "Installing Python 3..."
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        apt-get update && apt-get install -y python3 python3-pip
    elif [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ] || [ "$OS" = "centos" ]; then
        dnf install -y python3 python3-pip
    fi
fi
echo ""

# Check BCC
BCC_NEEDS_UPDATE=0
if python3 -c "from bcc import BPF" 2>/dev/null; then
    BCC_VERSION=$(python3 -c "import bcc; print(bcc.__version__)" 2>/dev/null || echo "unknown")
    echo "✅ BCC installed: $BCC_VERSION"
    
    # Check if version supports ring buffer (need >= 0.16.0)
    BCC_MAJOR=$(echo $BCC_VERSION | cut -d. -f1)
    BCC_MINOR=$(echo $BCC_VERSION | cut -d. -f2)
    if [ "$BCC_MAJOR" -lt 1 ] && ([ "$BCC_MAJOR" -eq 0 ] && [ "$BCC_MINOR" -lt 16 ]); then
        echo "⚠️  BCC version < 0.16.0: Ring buffer API not supported"
        BCC_NEEDS_UPDATE=1
    fi
else
    echo "❌ BCC not found"
    echo "Installing BCC..."
    
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        # Try to install from iovisor repo (may have newer version)
        apt-get update
        apt-get install -y software-properties-common
        
        # Check if iovisor repo exists and is valid
        IOVISOR_REPO_ADDED=0
        if ! grep -q "repo.iovisor.org" /etc/apt/sources.list.d/*.list 2>/dev/null; then
            echo "📥 Adding iovisor repository..."
            apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD 2>/dev/null || true
            echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/iovisor.list
            IOVISOR_REPO_ADDED=1
        fi
        
        # Try to update with iovisor repo
        if apt-get update 2>&1 | grep -q "repo.iovisor.org.*404\|does not have a Release file"; then
            echo "⚠️  iovisor repository not available for $(lsb_release -cs)"
            echo "   Removing invalid repository..."
            rm -f /etc/apt/sources.list.d/iovisor.list
            apt-get update
            echo "   Will try to install from Ubuntu/Debian repositories or build from source"
        fi
        
        # Try to install from package manager
        if apt-get install -y bpfcc-tools libbpfcc libbpfcc-dev python3-bpfcc 2>/dev/null; then
            echo "✅ BCC installed from package manager"
        else
            echo "⚠️  BCC not available in repositories"
            BCC_NEEDS_UPDATE=1
        fi
    elif [ "$OS" = "fedora" ]; then
        dnf install -y bcc-tools bcc-devel python3-bcc || BCC_NEEDS_UPDATE=1
    elif [ "$OS" = "rhel" ] || [ "$OS" = "centos" ]; then
        echo "⚠️  RHEL/CentOS: Please install BCC from source or EPEL"
        echo "   See: https://github.com/iovisor/bcc/blob/master/INSTALL.md"
        BCC_NEEDS_UPDATE=1
    fi
fi

# If BCC version is too old, suggest building from source
if [ "$BCC_NEEDS_UPDATE" -eq 1 ]; then
    echo ""
    echo "⚠️  To enable ring buffer support, you need BCC >= 0.16.0"
    echo "   Current version may not support ring buffer API"
    echo ""
    echo "   Options:"
    echo "   1. Build BCC from source (recommended):"
    echo "      git clone https://github.com/iovisor/bcc.git"
    echo "      cd bcc && mkdir build && cd build"
    echo "      cmake .. && make && sudo make install"
    echo ""
    echo "   2. Continue with current BCC (will use perf buffer):"
    echo "      This is fine - perf buffer works well, just ~30% slower"
    echo ""
    read -p "   Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled. Please update BCC first."
        exit 1
    fi
fi
echo ""

# Check kernel headers
KERNEL_HEADERS="linux-headers-$(uname -r)"
if [ -d "/usr/src/$KERNEL_HEADERS" ] || [ -d "/lib/modules/$(uname -r)/build" ]; then
    echo "✅ Kernel headers found"
else
    echo "❌ Kernel headers not found"
    echo "Installing kernel headers..."
    
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        apt-get install -y "$KERNEL_HEADERS" || apt-get install -y linux-headers-generic
    elif [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ] || [ "$OS" = "centos" ]; then
        dnf install -y kernel-devel kernel-headers
    fi
fi
echo ""

# Check required Python packages
echo "📚 Checking Python packages..."
python3 -c "import ctypes" 2>/dev/null && echo "✅ ctypes" || echo "❌ ctypes (should be built-in)"
python3 -c "import csv" 2>/dev/null && echo "✅ csv" || echo "❌ csv (should be built-in)"
echo ""

# Test BCC ring buffer support
echo "🔍 Testing BCC ring buffer support..."
RING_BUFFER_AVAILABLE=0
if python3 -c "from bcc import BPF; b = BPF(text='BPF_RINGBUF_OUTPUT(events, 4);'); print('supported' if hasattr(b['events'], 'open_ring_buffer') else 'not_supported')" 2>/dev/null | grep -q "supported"; then
    echo "✅ Ring buffer API available"
    RING_BUFFER_AVAILABLE=1
else
    echo "⚠️  Ring buffer API not available (will use perf buffer)"
    echo "   Reason: BCC version too old (< 0.16.0) or kernel < 5.8"
    echo "   Solution: Update BCC to >= 0.16.0 from source (see above)"
fi
echo ""

# Final check
echo "=== Final Check ==="
if python3 -c "from bcc import BPF" 2>/dev/null && [ -d "/lib/modules/$(uname -r)/build" ]; then
    echo "✅ Setup complete! You can now run: sudo python3 detector.py"
    exit 0
else
    echo "❌ Setup incomplete. Please check errors above."
    exit 1
fi

