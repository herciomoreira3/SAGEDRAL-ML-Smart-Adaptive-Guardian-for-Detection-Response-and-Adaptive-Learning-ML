# SAGEDRAL-ML

> **S**mart **A**daptive **G**uardian for **E**nhanced **D**etection, **R**esponse, and **A**daptive **L**earning — **ML**

SAGEDRAL-ML is an installable CLI tool and daemon for Linux systems that operates as a lightweight **Network Intrusion Detection and Prevention System (NIDPS)** powered by Machine Learning (LightGBM) and Signature Rules, integrated with `nftables`/`iptables` active IPS blocking and a real-time React web dashboard.

---

## 🌟 Key Features

- ⚡ **Real-time Packet Capture**: Non-blocking promiscuous mode packet sniffing via Scapy.
- 📊 **Flow Feature Extraction**: Aggregates raw packets into 5-tuple flow records and extracts 28 statistical network features.
- 🛡️ **Hybrid Threat Detection**:
  - **Signature Engine**: Rule-based detection for SYN Flood, ICMP Flood, UDP Flood, Port Scanning, SSH/RDP Brute Force, and Data Exfiltration.
  - **LightGBM ML Engine**: Two-stage detection (Binary Anomaly Detection + Multiclass Attack Classifier).
  - **Decision Engine**: Combines signature and anomaly scores with strict deduplication and threshold tuning.
- 🚫 **Active IPS Prevention**: Automatic IP blocking using native `nftables` or `iptables` with robust whitelist protection against self-blocking.
- 📱 **Real-Time Web Dashboard**: Built with React 18, Vite, Tailwind CSS, Recharts, and WebSockets for monitoring traffic stats, alerts, and system configuration.
- ⚙️ **Installable CLI Tool**: Complete `sagedral-ml` CLI command-line interface and systemd service integration.

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/sagedral-ml.git
cd sagedral-ml

# Run automated Linux installer (as root / sudo)
sudo bash scripts/install.sh
```

### Basic CLI Commands

```bash
# Check service status
sagedral-ml status

# Start daemon
sagedral-ml start --daemon

# View active configuration
sagedral-ml config show

# Manually block an IP
sagedral-ml block 192.168.1.100 --duration 3600

# View latest alerts
sagedral-ml alerts list
```

### Access Dashboard

Navigate to `http://localhost:8000` in your web browser.

---

## 📄 Documentation

For full architectural specifications, API contracts, module definitions, and database schemas, see **[prd.md](prd.md)**.
