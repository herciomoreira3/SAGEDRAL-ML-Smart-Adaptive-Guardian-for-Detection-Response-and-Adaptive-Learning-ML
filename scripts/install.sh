#!/bin/bash
# SAGEDRAL-ML Automated Installer Script
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

echo "================================================"
echo "  SAGEDRAL-ML Installer v1.0.0"
echo "  Smart Adaptive Guardian (NIDPS)"
echo "================================================"

# 1. Root privilege check
[[ $EUID -ne 0 ]] && error "Installer must be run as root (use: sudo bash scripts/install.sh)"

# 2. Install system dependencies
info "Installing system dependencies..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y python3-pip python3-dev libpcap-dev nftables tcpdump
elif command -v yum &>/dev/null; then
    yum install -y python3-pip python3-devel libpcap-devel nftables tcpdump
fi

# 3. Install Python dependencies and package
info "Installing dependencies from requirements.txt..."
pip install -r requirements.txt
info "Installing sagedral-ml Python package..."
pip install .

# 4. Create directories
info "Creating directories..."
mkdir -p /var/lib/sagedral-ml/models
mkdir -p /etc/sagedral
mkdir -p /var/log

# 5. Config template
if [[ ! -f /etc/sagedral/config.toml ]]; then
    sagedral-ml config template > /etc/sagedral/config.toml
    info "Created default config at /etc/sagedral/config.toml"
fi

# 6. Initialize nftables table
info "Initializing nftables sagedral table..."
nft add table inet sagedral 2>/dev/null || true
nft add set inet sagedral blocklist "{ type ipv4_addr; }" 2>/dev/null || true
nft add chain inet sagedral input "{ type filter hook input priority 0; }" 2>/dev/null || true
nft add rule inet sagedral input ip saddr @blocklist drop 2>/dev/null || true

# 7. Install systemd service
info "Installing systemd service..."
cat > /etc/systemd/system/sagedral-ml.service << 'EOF'
[Unit]
Description=SAGEDRAL-ML Network Intrusion Detection and Prevention System
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sagedral-ml start
Restart=on-failure
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sagedral-ml
info "Systemd service installed and enabled."

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  SAGEDRAL-ML installation completed!${NC}"
echo -e "${GREEN}================================================${NC}"
echo "Start service: systemctl start sagedral-ml"
echo "Web Dashboard: http://localhost:8000"
