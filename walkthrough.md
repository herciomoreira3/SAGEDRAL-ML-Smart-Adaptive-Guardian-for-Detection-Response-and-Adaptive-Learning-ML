# SAGEDRAL-ML — Panduan Instalasi & Menjalankan di WSL

> Tools NIDPS Machine Learning System — Smart Adaptive Guardian for Detection, Response and Adaptive Learning

---

## Status Implementasi Saat Ini

| Komponen | Status |
|---|---|
| Config Manager (TOML) | ✅ Selesai |
| Feature Extraction (FlowRecord) | ✅ Selesai |
| Signature Engine (5 rules) | ✅ Selesai |
| ML Engine (LightGBM + Anomaly) | ✅ Selesai |
| Decision Engine (Hybrid Score) | ✅ Selesai |
| IPS Module (nftables/iptables) | ✅ Selesai |
| Packet Capture (Scapy) | ✅ Selesai |
| Database (SQLite + SQLAlchemy) | ✅ Selesai |
| FastAPI Backend + WebSocket | ✅ Selesai |
| React Dashboard | ✅ Selesai |
| CLI (`sagedral-ml`) | ✅ Selesai |
| Systemd Service | ✅ Selesai |
| Test Suite (25 tests) | ✅ 25/25 PASS |
| Demo Seed Data | ✅ Selesai |

---

## Demo di Windows (Langsung)

Server sudah berjalan! Akses dashboard di:

**http://localhost:8000**

Untuk mengisi data demo:
```powershell
cd "c:\Users\HP\Hercio\SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML"
py -m scripts.seed_demo
```

---

## Cara Menjalankan di WSL (Full Linux Mode)

### Prasyarat
Buka WSL terminal (`wsl` di PowerShell atau Windows Terminal → Ubuntu).

### Step 1 — Clone / Copy Project ke WSL

```bash
# Opsi A: Akses langsung dari Windows filesystem
cd /mnt/c/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML

# Opsi B: Copy ke home WSL (lebih cepat I/O)
cp -r /mnt/c/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML ~/sagedral-ml
cd ~/sagedral-ml
```

### Step 2 — Install Dependencies System

```bash
sudo apt-get update
sudo apt-get install -y \
    python3 python3-pip python3-venv \
    libpcap-dev nftables iptables \
    build-essential curl git
```

### Step 3 — Setup Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

### Step 4 — Jalankan Test Suite

```bash
python -m pytest tests/ -v
# Expected: 25 passed
```

### Step 5 — Seed Data Demo

```bash
python -m scripts.seed_demo
```

### Step 6 — Jalankan Server API

```bash
# Mode development (tanpa root, tanpa packet capture)
python -m uvicorn sagedral_ml.api.main:app --host 0.0.0.0 --port 8000 --reload
```

Akses dashboard di browser: **http://localhost:8000**

### Step 7 — Jalankan Full System (Butuh Root untuk Capture + IPS)

```bash
# Harus root untuk Scapy dan nftables
sudo -E .venv/bin/python -m sagedral_ml.main

# Atau gunakan CLI:
sudo sagedral-ml start --interface eth0
```

---

## API Endpoints yang Tersedia

| Method | Endpoint | Deskripsi |
|---|---|---|
| GET | `/api/v1/status` | Status sistem & uptime |
| GET | `/api/v1/alerts` | Daftar alert (dengan filter) |
| GET | `/api/v1/blocked-ips` | IP yang diblokir |
| POST | `/api/v1/blocked-ips` | Manual block IP |
| DELETE | `/api/v1/blocked-ips/{ip}` | Unblock IP |
| GET | `/api/v1/traffic/stats` | Statistik traffic |
| GET | `/api/v1/config` | Lihat konfigurasi |
| PUT | `/api/v1/config` | Update konfigurasi |
| GET | `/api/v1/model/info` | Info model ML |
| POST | `/api/v1/model/retrain` | Trigger retrain model |
| GET | `/api/v1/rules` | Signature rules |
| WS | `/ws/alerts` | WebSocket real-time alerts |
| GET | `/docs` | Swagger UI / API Docs |

---

## Konfigurasi System

File konfigurasi utama: `config/sagedral-ml.toml`

```toml
[capture]
interface = "eth0"        # Ganti sesuai interface jaringan
promiscuous = true
bpf_filter = ""

[detection]
ml_threshold = 0.65
signature_enabled = true
anomaly_enabled = true

[ips]
auto_block = true
auto_unblock_after = 3600
whitelist = ["127.0.0.1", "10.0.0.0/8"]

[api]
host = "0.0.0.0"
port = 8000

[database]
path = "/var/lib/sagedral-ml/sagedral.db"
```

---

## Training Model ML

```bash
# Generate training data dan train model
python -m sagedral_ml.training.train_model \
    --data data/training/ \
    --output models/

# Atau gunakan CLI
sagedral-ml train --data data/training/
```

---

## Systemd Service (Production di Linux)

```bash
# Install sebagai service
sudo scripts/install.sh

# Start / Stop / Status
sudo systemctl start sagedral-ml
sudo systemctl stop sagedral-ml
sudo systemctl status sagedral-ml

# Lihat logs
sudo journalctl -u sagedral-ml -f
```

---

## Troubleshooting

**Port 8000 sudah dipakai:**
```bash
# Ganti port
python -m uvicorn sagedral_ml.api.main:app --port 8080
```

**Error `No module named 'sagedral_ml'`:**
```bash
pip install -e .
# atau
export PYTHONPATH=$(pwd)
```

**Scapy permission error:**
```bash
sudo setcap cap_net_raw=eip $(which python3)
# atau jalankan dengan sudo
```

**nftables tidak ditemukan (WSL):**
```bash
# WSL memiliki kernel terbatas, gunakan mode API-only:
SAGEDRAL_IPS_BACKEND=log python -m sagedral_ml.main
```

> [!NOTE]
> Dashboard dan API penuh berjalan tanpa root. Root hanya diperlukan untuk packet capture (Scapy) dan IPS action (nftables/iptables).
