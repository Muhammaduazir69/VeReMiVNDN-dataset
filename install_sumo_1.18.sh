#!/bin/bash
#
# Install SUMO 1.18.0 (API v21, compatible with Veins 5.3.1 and GCC 14)
#

set -e  # Exit on error

echo "=================================================="
echo "Installing SUMO 1.18.0 for Veins 5.3.1"
echo "=================================================="

# Step 1: Install dependencies
echo ""
echo "[Step 1/5] Installing build dependencies..."
sudo apt-get update || echo "Warning: apt-get update had some errors, continuing anyway..."
sudo apt-get install -y \
    cmake python3 g++ libxerces-c-dev libfox-1.6-dev \
    libgdal-dev libproj-dev libgl2ps-dev python3-dev \
    swig default-jdk maven libeigen3-dev \
    libgtest-dev libgoogle-perftools-dev libgrpc++-dev \
    protobuf-compiler-grpc

# Step 2: Download SUMO 1.18.0
echo ""
echo "[Step 2/5] Downloading SUMO 1.18.0..."
cd /tmp
rm -rf sumo-1.18.0
wget https://sourceforge.net/projects/sumo/files/sumo/version%201.18.0/sumo-src-1.18.0.tar.gz
tar xzf sumo-src-1.18.0.tar.gz
cd sumo-1.18.0

# Step 3: Configure build
echo ""
echo "[Step 3/5] Configuring build..."
mkdir -p build/cmake-build
cd build/cmake-build

# Configure with minimal GUI to avoid potential issues
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      ../..

# Step 4: Build SUMO
echo ""
echo "[Step 4/5] Building SUMO (this will take 10-15 minutes)..."
make -j$(nproc)

# Step 5: Install SUMO
echo ""
echo "[Step 5/5] Installing SUMO..."
sudo make install
sudo ldconfig

echo ""
echo "=================================================="
echo "SUMO 1.18.0 installation complete!"
echo "=================================================="
echo ""
echo "Verifying installation:"
/usr/local/bin/sumo --version | head -3
echo ""
echo "Environment is already configured in ~/.bashrc"
echo "Run: source ~/.bashrc"
echo ""
