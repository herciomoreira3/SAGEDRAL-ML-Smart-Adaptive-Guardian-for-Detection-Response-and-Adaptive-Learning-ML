#!/bin/bash
# SAGEDRAL-ML Uninstaller Script
set -euo pipefail

echo "Stopping systemd service..."
systemctl stop sagedral-ml 2>/dev/null || true
systemctl disable sagedral-ml 2>/dev/null || true

rm -f /etc/systemd/system/sagedral-ml.service
systemctl daemon-reload 2>/dev/null || true

echo "Removing nftables table..."
nft delete table inet sagedral 2>/dev/null || true

echo "Uninstalling Python package..."
pip3 uninstall -y sagedral-ml 2>/dev/null || true
pip uninstall -y sagedral-ml 2>/dev/null || true

echo "Cleaning up ML model files (remove /var/lib/sagedral-ml/models)..."
if [[ -d /var/lib/sagedral-ml/models ]]; then
    rm -f /var/lib/sagedral-ml/models/anomaly_detector.pkl
    rm -f /var/lib/sagedral-ml/models/attack_classifier.pkl
    rm -f /var/lib/sagedral-ml/models/feature_names.json
fi

echo "SAGEDRAL-ML uninstalled successfully."
echo ""
echo "Note: Database (/var/lib/sagedral-ml/sagedral.db), config (/etc/sagedral/config.toml), and"
echo "      logs (/var/log/sagedral-ml.log) have been PRESERVED. Delete them manually if desired:"
echo "        sudo rm -rf /var/lib/sagedral-ml /etc/sagedral /var/log/sagedral-ml.log"
