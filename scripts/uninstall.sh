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
pip uninstall -y sagedral-ml 2>/dev/null || true

echo "SAGEDRAL-ML uninstalled successfully."
