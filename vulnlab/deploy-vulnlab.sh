#!/bin/bash
#
# VulnLab Deployment Script for Ubuntu VM
# Deploys VulnLab alongside existing DVWA installation
#

set -e  # Exit on error

echo "=========================================="
echo "VulnLab Ubuntu VM Deployment"
echo "=========================================="
echo ""

# Check if running as root/sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo: sudo bash deploy-vulnlab.sh"
    exit 1
fi

# Configuration
VULNLAB_USER="www-data"  # Same user as Apache (DVWA)
VULNLAB_DIR="/var/www/vulnlab"
VULNLAB_PORT=5000
PYTHON_BIN="/usr/bin/python3"

echo "[1/6] Installing Python dependencies..."
apt-get update
apt-get install -y python3 python3-pip python3-venv

echo "[2/6] Creating VulnLab directory..."
mkdir -p $VULNLAB_DIR
cd $VULNLAB_DIR

echo "[3/6] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[4/6] Installing Flask..."
pip install Flask==3.0.0 Werkzeug==3.0.1

echo "[5/6] Copying VulnLab application..."
# The vulnlab.py file should be uploaded to /tmp/vulnlab.py first
if [ -f "/tmp/vulnlab.py" ]; then
    cp /tmp/vulnlab.py $VULNLAB_DIR/vulnlab.py
    chmod 644 $VULNLAB_DIR/vulnlab.py
else
    echo "ERROR: Please upload vulnlab.py to /tmp/vulnlab.py first"
    echo "Run on your Windows machine:"
    echo "  scp vulnlab.py user@20.2.209.236:/tmp/"
    exit 1
fi

echo "[6/6] Setting permissions..."
chown -R $VULNLAB_USER:$VULNLAB_USER $VULNLAB_DIR

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "VulnLab installed to: $VULNLAB_DIR"
echo "Will run on port: $VULNLAB_PORT"
echo ""
echo "Next steps:"
echo "1. Create systemd service: sudo cp /tmp/vulnlab.service /etc/systemd/system/"
echo "2. Enable service: sudo systemctl enable vulnlab"
echo "3. Start service: sudo systemctl start vulnlab"
echo "4. Check status: sudo systemctl status vulnlab"
echo "5. Open firewall: sudo ufw allow $VULNLAB_PORT/tcp"
echo ""
echo "Access VulnLab at: http://YOUR_VM_IP:$VULNLAB_PORT"
echo ""
