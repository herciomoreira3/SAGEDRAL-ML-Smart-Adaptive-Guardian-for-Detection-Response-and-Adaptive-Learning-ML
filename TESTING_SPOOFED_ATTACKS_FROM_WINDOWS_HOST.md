# PANDUAN TESTING SERANGAN SPOOFED DARI WINDOWS HOST KE BACKBOX VM

> **Topologi**: Windows HOST = Attacker (menjalankan spoofed_*.py dengan SOURCE IP SPOOFED ACAK)
>                BackBox VM  = Target + SAGEDRAL-ML NIDPS (mendeteksi + memblok IP FAKE)
>
> **Keamanan Utama**: Semua script attacker memakai **100% IP SOURCE SPOOFED RANDOM**
> (rentang 1-223.x.x.x, menghindari 10.x/172.16-31.x/192.168.x/127.x).
> **IP ASLI WINDOWS HOST ANDA TIDAK AKAN PERNAH TERPAKAI SEBAGAI SUMBER SERANGAN**
> → SAGEDRAL-ML hanya akan memblok IP FAKE → IP Windows host tetap aman, koneksi VM/SSH/RDP tidak terputus.

---

## 📋 DAFTAR ISI

1. [Topologi + Alur Paket](#1-topologi--alur-paket)
2. [Pre-Flight Checklist (WAJIB LULUS SEBELUM SERANGAN)](#2-pre-flight-checklist-wajib-lulus-sebelum-serangan)
3. [Setup Tools di Windows Host (Attacker Side)](#3-setup-tools-di-windows-host-attacker-side)
4. [Setup Live Monitor di BackBox VM (Target Side)](#4-setup-live-monitor-di-backbox-vm-target-side)
5. [Skenario 1: SPOOFED SYN FLOOD (DDoS)](#5-skenario-1-spoofed-syn-flood-ddos)
6. [Skenario 2: SPOOFED PORT SCAN](#6-skenario-2-spoofed-port-scan)
7. [Skenario 3: SPOOFED BRUTE FORCE SIGNATURE](#7-skenario-3-spoofed-brute-force-signature)
8. [Skenario 4: SPOOFED UDP FLOOD](#8-skenario-4-spoofed-udp-flood)
9. [Cara Verifikasi Hasil Serangan (Dashboard + CLI + NFT)](#9-cara-verifikasi-hasil-serangan-dashboard--cli--nft)
10. [Troubleshooting Serangan Tidak Terdeteksi](#10-troubleshooting-serangan-tidak-terdeteksi)

---

## 1. TOPOLOGI + ALUR PAKET

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  WINDOWS HOST (ATTACKER) — IP Anda: 192.168.1.100 / WiFi/Ethernet          │
│                                                                             │
│  ┌─ Scripts spoofed_*.py ──────────────────────────────────────────────┐   │
│  │ • spoofed_syn_flood.py  → SYN Flood (src IP FAKE ACAK 5.188.x.x dll) │   │
│  │ • spoofed_portscan.py  → Port Scan   (src IP FAKE ACAK tiap probe)   │   │
│  │ • spoofed_brute_force.py→ BruteForce Sig (src IP FAKE ACAK)          │   │
│  │ • spoofed_udp_flood.py → UDP Flood   (src IP FAKE ACAK)              │   │
│  └──────────────────────────────────────── via Npcap (raw socket) ───────┘   │
│                                  │ L2 frame src MAC asli (bisa di-spoof lagi)│
│                                  ▼                                           │
│                      BRIDGED ADAPTER VirtualBox (Layer 2)                    │
│                                  │                                           │
└──────────────────────────────────┼───────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  BACKBOX VM (TARGET + NIDPS) — IP Bridged: 192.168.1.123 (eth1)            │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ SAGEDRAL-ML                                                          │   │
│  │  ① Scapy AsyncSniffer (promisc) @ eth1 ← menangkap PAKET SPOOFED   │   │
│  │  ② Feature Extractor (29 feature CICFlowMeter)                      │   │
│  │  ③ ML 2-Stage:                                                       │   │
│  │        Stage-A LGBM AnomalyDetector    (anomaly_score >0.5 → alert)  │   │
│  │        Stage-B LGBM AttackClassifier   (label: PortScan/DDoS/BruteForce)│   │
│  │  ④ Decision Engine → severity > block_threshold → IPS Action        │   │
│  │  ⑤ IPS Response: nft add element inet sagedral blocklist { FAKE_IP }│   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Hasil Akhir:                                                               │
│   • DASHBOARD (http://192.168.1.123:8000) menampilkan Alerts + Blocked IPs │   │
│   • CLI: sagedral-ml alerts list → terlihat attack_class DDoS/PortScan     │   │
│   • NFT: sudo nft list set inet sagedral blocklist → penuh IP FAKE SPOOFED │   │
│   • IP WINDOWS ANDA (192.168.1.100) TIDAK PERNAH ADA DI BLOCKLIST ✅       │   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. PRE-FLIGHT CHECKLIST (WAJIB LULUS SEBELUM SERANGAN)

Jalankan SEMUA perintah ini **DI DALAM BACKBOX VM** dan pastikan hasilnya sesuai:

| # | Perintah (BackBox Terminal) | Hasil yang DIHARAPKAN | Status |
|---|-----------------------------|-----------------------|--------|
| 1 | `python3 --version` | `Python 3.8.10` | ☐ |
| 2 | `sudo systemctl is-active sagedral-ml` | `active` | ☐ |
| 3 | `sagedral-ml status \| grep -E 'RUNNING|ML Model Loaded'` | `RUNNING` + `ML Model Loaded:   True` ✅ | ☐ |
| 4 | `sagedral-ml model info \| python3 -c 'import json,sys; d=json.load(sys.stdin); print("loaded:", d.get("loaded"))'` | `loaded: True` | ☐ |
| 5 | `ip -br addr show \| grep UP \| head` | Paling tidak 2 interface: `eth0/NAT` + `eth1/Bridged` (misal eth1 UP) | ☐ |
| 6 | `grep -E '^interface' /etc/sagedral/config.toml` | `interface = "eth1"` (atau nama interface bridged ANDA) | ☐ |
| 7 | `sudo nft list set inet sagedral blocklist \| head` | Perintah TIDAK error (table+set ada) | ☐ |
| 8 | **Dari Windows host** ping ke IP VM: `ping 192.168.1.123 -t` 3 detik → lalu `Ctrl+C` | Reply terus-menerus, tidak RTO = konektivitas OK | ☐ |

**⚠️ JIKA ADA 1 PUN TIDAK SESUAI → STOP. Perbaiki dulu (installer / konfigurasi) sebelum testing!**

---

## 3. SETUP TOOLS DI WINDOWS HOST (ATTACKER SIDE)

Semua script attacker ada di repo folder `scripts/testing/`. Tools yang dibutuhkan di Windows:

### 3.1 Install Npcap (WAJIB di Windows untuk raw socket / spoofed IP)

Tanpa Npcap, Scapy di Windows **tidak bisa mengirim paket dengan SPOOFED IP** (hanya bisa kirim IP asli host).

```
1. Kunjungi https://npcap.com/#download
2. Download Npcap Installer (misal npcap-1.79.exe)
3. Run installer sebagai Administrator
4. ⚠️ CENTANG opsi:
     ✅ Install Npcap in WinPcap API-compatible Mode
     ✅ Restrict Npcap driver's access to Administrators only
     (lainnya default)
5. Finish, lalu RESTART Windows (jika diminta)
6. Setelah restart, buka CMD Admin:
   sc query npcap
   → STATE: RUNNING  ✅
```

### 3.2 Install Python + Scapy di Windows Host

**Di Windows CMD / PowerShell Admin**:
```cmd
:: Cek python sudah ada
python --version   :: minimal 3.8+

:: Upgrade pip
python -m pip install --upgrade pip setuptools wheel

:: Install Scapy (versi stabil)
python -m pip install scapy==2.5.0
```

### 3.3 Clone / Copy Repo ke Folder Windows

Repo baru saja kita push dengan commit `1c8e54c`. Di Windows host:
```cmd
cd C:\Users\HP\
git clone https://github.com/herciomoreira3/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML.git sagedral-ml
cd sagedral-ml
git log --oneline -3
:: pastikan commit paling atas = 1c8e54c feat(py38)

:: Masuk ke folder testing scripts
cd scripts\testing
dir
```

Anda harus melihat 5 file: `spoofed_syn_flood.py`, `spoofed_portscan.py`, `spoofed_brute_force.py`, `spoofed_udp_flood.py`, `vm_side_monitor.py`.

### 3.4 Tes Scapy + Npcap Kirim 1 Paket SPOOFED (Smoke Test)

Buat file `smoke_test.py` di folder scripts\testing:
```python
from scapy.all import IP, ICMP, send, conf
conf.verb = 0
# Target = IP BackBox VM ANDA (ganti!)
TARGET = "192.168.1.123"
# SPOOFED src IP (bukan IP Windows Anda!)
FAKE = "5.188.10.20"
pkt = IP(src=FAKE, dst=TARGET) / ICMP()
send(pkt, count=3)
print(f"[OK] Sent 3 ICMP echo spoofed src={FAKE} dst={TARGET}")
```

Jalankan CMD sebagai **ADMINISTRATOR**:
```cmd
cd C:\Users\HP\sagedral-ml\scripts\testing
python smoke_test.py
```

Jika output `[OK] Sent 3 ICMP echo` → Scapy + Npcap jalan, spoofed IP WORK ✅.
Jika error "No permission / no /dev/bpf" → Npcap belum terinstall / belum di-RunAs Admin.

---

## 4. SETUP LIVE MONITOR DI BACKBOX VM (TARGET SIDE)

Buka **Terminal baru di BackBox VM** (biarkan tetap terbuka selama testing):

```bash
# Pastikan masuk ke repo
cd ~/sagedral-ml

# (HANYA JIKA BELUM ADA file ini di BackBox)
# Karena repo sudah di-push, git pull dulu:
git pull origin main

# Jalankan LIVE MONITOR (refresh setiap 2 detik)
sudo python3 scripts/testing/vm_side_monitor.py --i 2
```

Biarkan jendela monitor ini menyala. Selama serangan berjalan, Anda akan melihat LIVE:
- Service: `active`
- Blocked IPs count: bertambah naik drastis (seluruhnya IP FAKE)
- Last 10 alerts: muncul label attack_class `DDoS` / `PortScan` / `BruteForce` / `WebAttack`
- Last 10 blocked IPs: **SEMUA ADALAH IP SPOOFED** (tidak ada 192.168.x Anda sendiri) ✅

---

## 5. SKENARIO 1: SPOOFED SYN FLOOD (DDoS)

### 5.1 Yang Terjadi di Jaringan
- `flow_packets_per_sec` → >500 pkt/s
- `syn_flag_count` → tinggi
- Src IP: 1000+ fake IP berbeda
- SAGEDRAL-ML Stage-A anomaly_score meledak (>0.5)
- Stage-B classifier → attack class = **DDoS**
- Decision Engine → severity ≥ 0.6 → **IP FAKE auto-block ke nftables**

### 5.2 Jalankan dari WINDOWS HOST CMD (Run as ADMIN)

```cmd
cd C:\Users\HP\sagedral-ml\scripts\testing

:: Ganti --target dengan IP BRIDGED BackBox VM ANDA!
python spoofed_syn_flood.py --target 192.168.1.123 --port 80 --pps 400 --duration 20
```

### 5.3 Yang Diamati di BackBox LIVE MONITOR
- Blocked IPs count: harus bertambah drastis
- Alert table: baris baru dengan attack_class = **DDoS**
- Di CLI terminal LAIN di BackBox:
```bash
sudo nft list set inet sagedral blocklist
sagedral-ml alerts list --limit 20
```

### 5.4 Verifikasi IP ASLI ANDA TIDAK KE-BLOCK
```bash
:: Di Windows host, selama/delahkan serangan, ping ke VM:
ping 192.168.1.123 -n 10
:: HARUSNYA reply terus (RTO = 0) karena IP ASLI Windows tidak pernah dijadikan src.
```

---

## 6. SKENARIO 2: SPOOFED PORT SCAN

### 6.1 Yang Terjadi
- `syn_flag_count` tinggi, dst_port bervariasi (top 100 port)
- Feature spread dst_port → classifier label = **PortScan**
- Auto-block beberapa IP scanner FAKE

### 6.2 Jalankan (Windows CMD ADMIN)
```cmd
cd C:\Users\HP\sagedral-ml\scripts\testing
python spoofed_portscan.py --target 192.168.1.123 --ports top100 --interval 0.015
```

### 6.3 Verifikasi (BackBox)
```bash
sagedral-ml alerts list --limit 30
# Cari baris dengan attack_class = "PortScan"
sudo nft list set inet sagedral blocklist | wc -l
```

---

## 7. SKENARIO 3: SPOOFED BRUTE FORCE SIGNATURE

### 7.1 Yang Terjadi
- Banyak SYN → RST pattern di port 22 / 3389 / 8080
- `rst_flag_count` tinggi terkonsentrasi di port auth
- Classifier label = **BruteForce**

### 7.2 Jalankan
```cmd
cd C:\Users\HP\sagedral-ml\scripts\testing
python spoofed_brute_force.py --target 192.168.1.123 --ports 22,3389,8080 --attempts-per-port 300 --duration 25
```

---

## 8. SKENARIO 4: SPOOFED UDP FLOOD

### 8.1 Yang Terjadi
- High PPS dengan payload random
- `flow_bytes_per_sec` dan `flow_packets_per_sec` meledak
- Anomaly score tinggi → label = **DDoS** (UDP variant)

### 8.2 Jalankan
```cmd
cd C:\Users\HP\sagedral-ml\scripts\testing
python spoofed_udp_flood.py --target 192.168.1.123 --port 53 --pps 500 --duration 18
```

---

## 9. CARA VERIFIKASI HASIL SERANGAN (3 LAYER)

### 9.1 Layer 1: CLI SAGEDRAL-ML
```bash
# Alerts terbaru
sagedral-ml alerts list --limit 30

# Status model (pastikan ML loaded=True tetap True)
sagedral-ml model info

# Service status
sagedral-ml status
```

### 9.2 Layer 2: nftables BLOCKLIST IPS (eksekusi sebenarnya)
```bash
# Count total IP blocked
sudo nft -j list set inet sagedral blocklist | python3 -c "
import json,sys
j=json.load(sys.stdin)
ips=[]
for o in j.get('nftables',[]):
    if 'set' in o and o['set'].get('name')=='blocklist':
        for e in o['set'].get('elem',[]):
            if isinstance(e,str): ips.append(e)
print(f'Total blocked: {len(ips)}')
print('Sample blocked IPs (FAKE):', ips[-10:])
"

# Pastikan IP host Windows ANDA TIDAK ADA DISINI:
# Misal host IP=192.168.1.100:
sudo nft list set inet sagedral blocklist | grep 192.168.1.100
# KOSONG = BERARTI HOST ANDA AMAN ✅ (benar-benar IP spoofed working)
```

### 9.3 Layer 3: Web Dashboard
Buka browser (bisa dari Windows host):
```
http://192.168.1.123:8000
```

Cek tab:
- **Overview**: Packets Total, Alerts Count, Blocked IP Count grafiknya menanjak
- **Alerts**: Click filter → attack class DDoS / PortScan / BruteForce muncul; Click baris → Detail modal menampilkan flow features
- **Blocked IPs**: Tabel penuh dengan IP SPOOFED (cek last 10) → klik kanan "Whois" → lokasi IP asal seharusnya RANDOM di berbagai negara
- **Traffic**: Graph PPS/bandwidth melejit selama fase serangan
- **Model Info**: Pastikan ML Loaded tetap True + thresholds normal

---

## 10. TROUBLESHOOTING SERANGAN TIDAK TERDETEKSI

| Symptom | Possible Root Cause | Fix |
|---------|---------------------|-----|
| Monitor: `Blocked IPs count: 0` terus | capture.interface di config salah (ke eth0 NAT, bukan eth1 bridged) | Ganti `interface = "eth1"` → `sudo systemctl restart sagedral-ml` |
| Live Monitor: Sniffer packets = 0 selama attack | Promiscuous mode VirtualBox BUKAN "Allow All" | Shutdown VM → VirtualBox GUI → Network → Bridged Adapter → Advanced → **Promiscuous Mode = Allow All** → Boot ulang VM |
| Alerts 0, tapi tcpdump lihat paket | `decision.alert_threshold` / `ml.anomaly_threshold` terlalu tinggi | Edit `/etc/sagedral/config.toml`: `anomaly_threshold=0.45, alert_threshold=0.35, block_threshold=0.55` → restart service |
| Script attacker Windows exit error "[FATAL] scapy not installed" | Scapy hanya terinstall di Python user lain | CMD Admin → `python -m pip install scapy==2.5.0` |
| Script attacker error "Unable to match routed IP" / "No /dev/bpf" | Npcap TIDAK terinstall / belum RunAs Admin | Install Npcap (centang WinPcap compatible), restart PC, jalankan CMD as Admin |
| SYN Flood attack send 0 pkt | Windows Firewall / 3rd-party AV (Avast/Kaspersky) filter raw socket | Temporarily disable Windows Defender Firewall → test. Setelah test enable lagi |
| Semua paket spoofed, tapi classifier = NORMAL / tidak block | SAGEDRAL-ML rule-based fallback aktif (lightgbm compile failure Py3.8) | `sudo apt-get install -y build-essential python3-dev libgomp1 && sudo sagedral-ml model init --force` |
| Blocked IPs ada, tapi `ssh` dari host masih OKE ✅ | Normal — yang diblok HANYA IP FAKE SPOOFED | — |

---

## 📂 REFERENSI SEMUA FILE TESTING

| File | Lokasi |
|------|--------|
| **Spoofed SYN Flood Attacker** (Windows/WSL) | [spoofed_syn_flood.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/scripts/testing/spoofed_syn_flood.py) |
| **Spoofed Port Scan Attacker** (Windows/WSL) | [spoofed_portscan.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/scripts/testing/spoofed_portscan.py) |
| **Spoofed BruteForce Signature** (Windows/WSL) | [spoofed_brute_force.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/scripts/testing/spoofed_brute_force.py) |
| **Spoofed UDP Flood Attacker** (Windows/WSL) | [spoofed_udp_flood.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/scripts/testing/spoofed_udp_flood.py) |
| **BackBox VM Live Monitor** (target side) | [vm_side_monitor.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/scripts/testing/vm_side_monitor.py) |
| Panduan Installer BackBox VM (Py3.8 Ready) | [INSTALL_BACKBOX_VIRTUALBOX.md](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/INSTALL_BACKBOX_VIRTUALBOX.md) |
