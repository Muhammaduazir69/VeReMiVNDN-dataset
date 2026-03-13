#!/bin/bash
#
# Install SUMO 1.10.0 (compatible with Veins 5.3.1)
#

set -e  # Exit on error

echo "=================================================="
echo "Installing SUMO 1.10.0 for Veins 5.3.1 compatibility"
echo "=================================================="

# 1. Remove current SUMO installation
echo ""
echo "[Step 1/5] Removing current SUMO 1.24.0..."
sudo apt-get remove --purge -y sumo sumo-tools sumo-doc 2>/dev/null || true
sudo apt-get autoremove -y

# 2. Install dependencies
echo ""
echo "[Step 2/5] Installing build dependencies..."
sudo apt-get update
sudo apt-get install -y \
    cmake python3 g++ libxerces-c-dev libfox-1.6-dev \
    libgdal-dev libproj-dev libgl2ps-dev swig

# 3. Download SUMO 1.10.0
echo ""
echo "[Step 3/5] Downloading SUMO 1.10.0..."
cd /tmp
if [ -d "sumo-1.10.0" ]; then
    rm -rf sumo-1.10.0
fi
wget https://sourceforge.net/projects/sumo/files/sumo/version%201.10.0/sumo-src-1.10.0.tar.gz/download -O sumo-1.10.0.tar.gz
tar xzf sumo-1.10.0.tar.gz
cd sumo-1.10.0

# 4. Build and install SUMO
echo ""
echo "[Step 4/5] Building SUMO 1.10.0 (this may take 10-15 minutes)..."
mkdir -p build/cmake-build
cd build/cmake-build
cmake ../..
make -j$(nproc)
sudo make install

# 5. Configure environment
echo ""
echo "[Step 5/5] Configuring SUMO environment..."
sudo ldconfig

# Add SUMO_HOME to bashrc if not already present
if ! grep -q "SUMO_HOME" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# SUMO environment" >> ~/.bashrc
    echo "export SUMO_HOME=/usr/local/share/sumo" >> ~/.bashrc
    echo "export PATH=\$PATH:\$SUMO_HOME/bin" >> ~/.bashrc
fi

# Apply environment variables for current session
export SUMO_HOME=/usr/local/share/sumo
export PATH=$PATH:$SUMO_HOME/bin

echo ""
echo "=================================================="
echo "SUMO 1.10.0 installation complete!"
echo "=================================================="
echo ""
echo "Installed version:"
sumo --version
echo ""
echo "Please run: source ~/.bashrc"
echo "Or restart your terminal to apply environment changes."
echo ""
echo "You can now run your simulation with:"
echo "./VeReMiVNDN -u Cmdenv -c BasicVNDN -f simulations/configs/omnetpp.ini \\"
echo "  -n src:simulations:../inet4.5/src:../veins/src/veins \\"
echo "  --image-path=../inet4.5/images:../veins/images"
echo ""
