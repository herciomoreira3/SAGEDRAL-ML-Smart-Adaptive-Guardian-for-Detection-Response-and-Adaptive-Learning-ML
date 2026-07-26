#!/bin/bash
# SAGEDRAL-ML Automated Installer Script
# v1.0.1 — Updated for Python 3.8.10 compatibility (BackBox / Ubuntu 20.04 LTS)
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

echo "================================================"
echo "  SAGEDRAL-ML Installer v1.0.1"
echo "  Smart Adaptive Guardian (NIDPS)"
echo "  Compatibility: Python >= 3.8 (tested Py3.8.10)"
echo "================================================"

# 1. Root privilege check
[[ $EUID -ne 0 ]] && error "Installer must be run as root (use: sudo bash scripts/install.sh)"

# 2. Python version pre-flight check
info "Checking Python version..."
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || echo "0.0.0")
    PY_MAJ=$(python3 -c 'import sys; print(sys.version_info[0])' 2>/dev/null || echo 0)
    PY_MIN=$(python3 -c 'import sys; print(sys.version_info[1])' 2>/dev/null || echo 0)
    info "Detected python3 version: ${PY_VER}"
    if [[ "$PY_MAJ" -lt 3 ]] || [[ "$PY_MIN" -lt 8 ]]; then
        error "SAGEDRAL-ML requires Python >= 3.8. Detected ${PY_VER}. Install python3.8+ and try again."
    fi
else
    error "python3 command not found. Please install python3 first."
fi

# 2b. Pip bootstrap (some minimal distros have python3 but no pip)
if ! command -v pip3 &>/dev/null; then
    warn "pip3 not found — trying to install python3-pip / bootstrap via ensurepip..."
    apt-get install -y python3-pip 2>/dev/null || \
    python3 -m ensurepip --upgrade 2>/dev/null || \
    (curl -sS https://bootstrap.pypa.io/get-pip.py | python3) || \
    error "Failed to install pip3. Install python3-pip manually then re-run installer."
fi

# 3. Install system dependencies
info "Installing system dependencies (python3-dev, libpcap, nftables, build-essential)..."
if command -v apt-get &>/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    # build-essential + python3-dev Wajib untuk compile lightgbm/numpy/scikit-learn C extensions di Py3.8
    apt-get install -y --no-install-recommends \
        python3-pip \
        python3-dev \
        python3-setuptools \
        build-essential \
        libpcap-dev \
        nftables \
        tcpdump \
        libgomp1 \
        ca-certificates \
        curl
elif command -v yum &>/dev/null; then
    yum install -y python3-pip python3-devel libpcap-devel nftables tcpdump gcc gcc-c++ libgomp
fi

# 4. Upgrade pip/setuptools/wheel terlebih dahulu (kritis untuk build Py3.8 wheels)
info "Upgrading pip, setuptools, and wheel for Python 3.8 build compatibility..."
pip3 install --upgrade pip setuptools wheel || \
    python3 -m pip install --upgrade pip setuptools wheel

# 5. Install Python dependencies from requirements.txt (version-capped for Py3.8)
info "Installing Python dependencies from requirements.txt (Py3.8-compatible version pins)..."
python3 -m pip install -r requirements.txt

# 6. Install sagedral-ml Python package
info "Installing sagedral-ml Python package..."
python3 -m pip install .

# 7. Verify sagedral-ml CLI accessible
if ! command -v sagedral-ml &>/dev/null; then
    # Fallback: cari di /usr/local/bin atau pip show location
    SAG_CLI=$(python3 -c 'import sysconfig; print(sysconfig.get_path("scripts"))' 2>/dev/null)/sagedral-ml
    if [[ -x "$SAG_CLI" ]]; then
        ln -sf "$SAG_CLI" /usr/local/bin/sagedral-ml 2>/dev/null || true
    fi
fi

# 8. Create directories
info "Creating directories..."
if ! id -u sagedral &>/dev/null; then
    useradd --system --home-dir /var/lib/sagedral-ml --shell /usr/sbin/nologin sagedral
fi
mkdir -p /var/lib/sagedral-ml/models
mkdir -p /var/lib/sagedral-ml/backups
mkdir -p /var/lib/sagedral-ml/custom-rules
mkdir -p /etc/sagedral
mkdir -p /var/log
touch /var/log/sagedral-ml.log
chown -R sagedral:sagedral /var/lib/sagedral-ml
chown sagedral:sagedral /var/log/sagedral-ml.log
chmod 0750 /var/lib/sagedral-ml
chmod 0640 /var/log/sagedral-ml.log

# 9. Config template
if [[ ! -f /etc/sagedral/config.toml ]]; then
    sagedral-ml config template > /etc/sagedral/config.toml
    chown root:sagedral /etc/sagedral/config.toml
    chmod 0660 /etc/sagedral/config.toml
    info "Created default config at /etc/sagedral/config.toml"
fi

# 10. Initialize nftables table
info "Initializing nftables sagedral table..."
nft add table inet sagedral 2>/dev/null || true
nft add set inet sagedral blocklist "{ type ipv4_addr; }" 2>/dev/null || true
nft add chain inet sagedral input "{ type filter hook input priority 0; }" 2>/dev/null || true
nft add rule inet sagedral input ip saddr @blocklist drop 2>/dev/null || true

# 11. ML Model initialization (CRITICAL — generates fallback models so ML Model Loaded = True on first start)
info "Initializing ML detection models (rule-based fallback if LightGBM can't compile yet)..."
if runuser -u sagedral -- sagedral-ml model init; then
    info "ML models initialized successfully."
else
    warn "ML model init returned non-zero. Service will generate fallbacks on first startup."
    info "If failure persists, run: sudo apt-get install -y build-essential libgomp1 && sudo sagedral-ml model init --force"
fi

# 12. Install systemd service + logrotate
info "Installing systemd service..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/../systemd/sagedral-ml.service" ]]; then
    cp "${SCRIPT_DIR}/../systemd/sagedral-ml.service" /etc/systemd/system/sagedral-ml.service
else
    cat > /etc/systemd/system/sagedral-ml.service << 'EOF'
[Unit]
Description=SAGEDRAL-ML Network Intrusion Detection and Prevention System
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sagedral-ml start
Restart=on-failure
RestartSec=10
WatchdogSec=120
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
fi

info "Installing logrotate configuration..."
if [[ -f "${SCRIPT_DIR}/logrotate.conf" ]]; then
    cp "${SCRIPT_DIR}/logrotate.conf" /etc/logrotate.d/sagedral-ml
    info "Logrotate config installed at /etc/logrotate.d/sagedral-ml"
fi

if [ -d /run/systemd/system ] && systemctl is-system-running &>/dev/null; then
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable sagedral-ml 2>/dev/null || true
    info "Systemd service installed and enabled."
    info "Starting SAGEDRAL-ML service..."
    systemctl start sagedral-ml 2>/dev/null || warn "Could not auto-start service. Start manually: systemctl start sagedral-ml"
else
    warn "System is not booted with systemd as PID 1 (WSL or container environment detected)."
    warn "Service file created at /etc/systemd/system/sagedral-ml.service"
    info "To start SAGEDRAL-ML manually, run: sudo sagedral-ml start"
fi

# 13. Post-install status check
echo ""
info "Post-install status check..."
sleep 2
if command -v sagedral-ml &>/dev/null; then
    echo ""
    echo "=== ML Model Status (offline check) ==="
    sagedral-ml model info 2>&1 || true
    echo ""
fi

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  SAGEDRAL-ML installation completed!${NC}"
echo -e "${GREEN}================================================${NC}"
echo "Supported Python: $(python3 --version) ✅"
echo ""
echo "Start service : systemctl start sagedral-ml"
echo "                (or non-systemd: sudo sagedral-ml start)"
echo "Check status  : sagedral-ml status          -> ML Model Loaded should now be True"
echo "Model details : sagedral-ml model info"
echo "Re-init model : sagedral-ml model init --force"
echo "Web Dashboard : http://localhost:8000"
echo ""
echo -e "${YELLOW}👉 NEXT STEP:${NC} Edit /etc/sagedral/config.toml and set capture.interface to your"
echo "   active Bridged/monitor interface (e.g. eth1), then restart service: systemctl restart sagedral-ml"
