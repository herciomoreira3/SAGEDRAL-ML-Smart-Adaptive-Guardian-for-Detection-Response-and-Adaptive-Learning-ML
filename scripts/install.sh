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
pip3 install -r requirements.txt
info "Installing sagedral-ml Python package (source with ML fallback fixes)..."
pip3 install .

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

# 7. ML Model initialization (CRITICAL FIX: generates fallback models so ML Model Loaded = True on first start)
info "Initializing ML detection models..."
if sagedral-ml model init; then
    info "ML models initialized successfully."
else
    warn "ML model init returned non-zero. Service will generate fallbacks on first startup."
fi

# 8. Install systemd service
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

if [ -d /run/systemd/system ] && systemctl is-system-running &>/dev/null; then
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable sagedral-ml 2>/dev/null || true
    info "Systemd service installed and enabled."
    info "Starting SAGEDRAL-ML service..."
    systemctl start sagedral-ml 2>/dev/null || warn "Could not auto-start service. Start manually: systemctl start sagedral-ml"
else
    warn "System is not booted with systemd as PID 1 (WSL environment detected)."
    warn "Service file created at /etc/systemd/system/sagedral-ml.service"
    info "To start SAGEDRAL-ML manually in WSL, run: sudo sagedral-ml start"
fi

# 9. Post-install status check
echo ""
info "Post-install status check..."
sleep 2
if command -v sagedral-ml &>/dev/null; then
    # Pre-flight offline model check (doesn't require running service)
    echo ""
    echo "=== ML Model Status (offline check) ==="
    sagedral-ml model info 2>&1 || true
    echo ""
fi

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  SAGEDRAL-ML installation completed!${NC}"
echo -e "${GREEN}================================================${NC}"
echo "Start service : systemctl start sagedral-ml"
echo "                (or WSL: sudo sagedral-ml start)"
echo "Check status  : sagedral-ml status          -> ML Model Loaded should now be True"
echo "Model details : sagedral-ml model info"
echo "Re-init model : sagedral-ml model init --force"
echo "Web Dashboard : http://localhost:8000"
