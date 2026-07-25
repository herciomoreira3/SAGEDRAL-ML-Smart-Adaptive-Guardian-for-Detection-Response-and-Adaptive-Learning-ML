# SAGEDRAL-ML — Panduan Dasar Topologi Jaringan & Implementasi

> **S**mart **A**daptive **G**uardian for **E**nhanced **D**etection, **R**esponse, and **A**daptive **L**earning — **ML**
>
> Versi: `1.0.0-basic`  
> Terakhir Diperbarui: `2026-07-25`  
> Target Pembaca: **Junior Network Engineer / Beginner**

---

## Daftar Isi

1. [Pendahuluan: Apa itu SAGEDRAL-ML?](#1-pendahuluan-apa-itu-sagedral-ml)
2. [Konsep Dasar Jaringan yang Harus Dipahami Dulu](#2-konsep-dasar-jaringan-yang-harus-dipahami-dulu)
   - 2.1 [Apa itu IP Address, Port, dan Protocol?](#21-apa-itu-ip-address-port-dan-protocol)
   - 2.2 [Apa itu Network Interface (NIC)?](#22-apa-itu-network-interface-nic)
   - 2.3 [Apa itu Packet dan Flow?](#23-apa-itu-packet-dan-flow)
   - 2.4 [Apa itu Gateway / Router?](#24-apa-itu-gateway--router)
   - 2.5 [Apa itu Firewall?](#25-apa-itu-firewall)
   - 2.6 [Apa itu IDS, IPS, dan NIDPS?](#26-apa-itu-ids-ips-dan-nidps)
3. [Arsitektur SAGEDRAL-ML secara Sederhana](#3-arsitektur-sagedral-ml-secara-sederhana)
   - 3.1 [9 Komponen Utama SAGEDRAL-ML](#31-9-komponen-utama-sagedral-ml)
   - 3.2 [Diagram Alir Data End-to-End](#32-diagram-alir-data-end-to-end)
4. [Tempat Meletakkan SAGEDRAL-ML di Jaringan](#4-tempat-meletakkan-sagedral-ml-di-jaringan)
   - 4.1 [Topologi 1: SAGEDRAL sebagai Gateway (Inline Mode) — PALING DIREKOMENDASIKAN](#41-topologi-1-sagedral-sebagai-gateway-inline-mode--paling-direkomendasikan)
   - 4.2 [Topologi 2: SAGEDRAL di Samping Router (Mirror / SPAN Port)](#42-topologi-2-sagedral-di-samping-router-mirror--span-port)
   - 4.3 [Topologi 3: SAGEDRAL sebagai Host IDS di Server Tunggal](#43-topologi-3-sagedral-sebagai-host-ids-di-server-tunggal)
   - 4.4 [Topologi 4: SAGEDRAL di Lab / Testing WSL2 (Untuk Belajar)](#44-topologi-4-sagedral-di-lab--testing-wsl2-untuk-belajar)
5. [Contoh Kasus Implementasi Langkah demi Langkah](#5-contoh-kasus-implementasi-langkah-demi-langkah)
   - 5.1 [Kasus A: Kantor Kecil (10-50 Karyawan) sebagai Gateway](#51-kasus-a-kantor-kecil-10-50-karyawan-sebagai-gateway)
   - 5.2 [Kasus B: Melindungi Server Web Publik](#52-kasus-b-melindungi-server-web-publik)
   - 5.3 [Kasus C: Lab Belajar di Laptop dengan WSL2](#53-kasus-c-lab-belajar-di-laptop-dengan-wsl2)
6. [Panduan Konfigurasi per Topologi](#6-panduan-konfigurasi-per-topologi)
   - 6.1 [Konfigurasi Dasar: Config.toml](#61-konfigurasi-dasar-configtoml)
   - 6.2 [Konfigurasi Interface untuk Gateway Mode](#62-konfigurasi-interface-untuk-gateway-mode)
   - 6.3 [Konfigurasi Whitelist Penting](#63-konfigurasi-whitelist-penting)
   - 6.4 [Konfigurasi Threshold Detection untuk Pemula](#64-konfigurasi-threshold-detection-untuk-pemula)
7. [Contoh Serangan yang Dapat Dideteksi SAGEDRAL-ML](#7-contoh-serangan-yang-dapat-dideteksi-sagedral-ml)
   - 7.1 [SYN Flood (DoS)](#71-syn-flood-dos)
   - 7.2 [Port Scanning](#72-port-scanning)
   - 7.3 [Brute Force SSH / RDP](#73-brute-force-ssh--rdp)
   - 7.4 [UDP Flood / ICMP Flood](#74-udp-flood--icmp-flood)
   - 7.5 [Data Exfiltration (Pencurian Data)](#75-data-exfiltration-pencurian-data)
8. [Cara Membaca Dashboard SAGEDRAL-ML](#8-cara-membaca-dashboard-sagedral-ml)
   - 8.1 [Halaman Overview: Ringkasan Umum](#81-halaman-overview-ringkasan-umum)
   - 8.2 [Halaman Alerts: Daftar Ancaman](#82-halaman-alerts-daftar-ancaman)
   - 8.3 [Halaman Blocked IPs: Daftar IP yang Diblokir](#83-halaman-blocked-ips-daftar-ip-yang-diblokir)
   - 8.4 [Halaman Traffic: Analisa Trafik](#84-halaman-traffic-analisa-trafik)
   - 8.5 [Halaman Settings: Pengaturan](#85-halaman-settings-pengaturan)
9. [Perintah CLI SAGEDRAL-ML yang Sering Digunakan](#9-perintah-cli-sagedral-ml-yang-sering-digunakan)
10. [Troubleshooting Umum untuk Pemula](#10-troubleshooting-umum-untuk-pemula)
    - 10.1 [SAGEDRAL tidak menangkap paket](#101-sagedral-tidak-menangkap-paket)
    - 10.2 [IP saya sendiri terblokir!](#102-ip-saya-sendiri-terblokir)
    - 10.3 [Dashboard tidak bisa diakses](#103-dashboard-tidak-bisa-diakses)
    - 10.4 [Terlalu banyak alert palsu (False Positive)](#104-terlalu-banyak-alert-palsu-false-positive)
11. [Glosarium Istilah Penting](#11-glosarium-istilah-penting)
12. [Cheat Sheet: Referensi Cepat](#12-cheat-sheet-referensi-cepat)

---

## 1. Pendahuluan: Apa itu SAGEDRAL-ML?

SAGEDRAL-ML adalah **alat keamanan jaringan** yang berfungsi sebagai **polisi lalu lintas** untuk jaringan komputer Anda.

Bayangkan sebuah **gerbang tol** di jalan raya:
- Setiap **kendaraan** = **packet** data di jaringan
- **Petugas tol** = **SAGEDRAL-ML**
- Petugas memeriksa setiap kendaraan: apakah ini kendaraan normal (antar jemput keluarga, pengiriman barang) atau kendaraan mencurigakan (mobil polisi palsu, truk membawa barang ilegal)
- Jika mencurigakan → **ditahan** (IP diblokir)
- Jika normal → **dilewatkan** (traffic diteruskan)
- Semua kejadian dicatat dalam **buku laporan** (database SQLite + Dashboard)

### Apa yang BISA dan TIDAK BISA SAGEDRAL-ML?

| ✅ BISA (Kemampuan) | ❌ TIDAK BISA (Keterbatasan v1.0) |
|---|---|
| Mendeteksi serangan DoS/DDoS (SYN Flood, UDP Flood) | Mendeteksi virus / malware di file (butuh antivirus) |
| Mendeteksi port scanning (orang memeriksa celah) | Membaca isi pesan terenkripsi HTTPS (butuh DPI + SSL Decrypt) |
| Mendeteksi brute force login (SSH/RDP) | Deploy multi-node / distributed |
| Memblokir IP penyerang OTOMATIS | Berjalan di Windows sebagai host (butuh Linux / WSL2) |
| Memantau trafik via dashboard web real-time | Menggunakan GPU untuk inference |
| Belajar adaptif dari data baru (retrain model) | - |
| Berjalan di mesin spek rendah (Core i3, 4GB RAM) | - |

---

## 2. Konsep Dasar Jaringan yang Harus Dipahami Dulu

> **💡 PENTING:** Bagian ini WAJIB dibaca dulu jika Anda masih baru di dunia networking. Tanpa memahami konsep ini, Anda akan kesulitan memahami cara kerja SAGEDRAL-ML.

---

### 2.1 Apa itu IP Address, Port, dan Protocol?

#### IP Address (Alamat IP)

> **Analogi:** Alamat rumah. Setiap perangkat di jaringan punya alamat unik agar paket data tahu mau dikirim ke mana.

Format: `XXX.XXX.XXX.XXX` (4 kelompok angka 0-255)

Contoh:
```
192.168.1.1     = Biasanya alamat router WiFi rumah Anda
192.168.1.100   = Laptop / HP Anda yang terhubung ke WiFi
8.8.8.8         = Server DNS Google (publik)
127.0.0.1       = "Loopback" / alamat perangkat itu sendiri
```

Jenis IP:
- **IP Publik**: Diberikan ISP, bisa diakses dari internet (contoh: 203.123.45.67)
- **IP Privat**: Hanya untuk jaringan lokal, tidak bisa diakses internet langsung (range: `10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`)

#### Port

> **Analogi:** Nomor kamar / nomor ruangan di sebuah gedung. Satu gedung (IP address) bisa punya banyak kamar (port), dan setiap kamar punya fungsi berbeda.

Satu perangkat (satu IP) bisa menjalankan BANYAK layanan sekaligus. Port membedakan layanan mana yang dituju.

Range: `0 - 65535`

Port Populer:
| Port | Protocol | Layanan | Keterangan |
|---|---|---|---|
| 22 | TCP | SSH | Remote login server Linux |
| 80 | TCP | HTTP | Website tidak aman |
| 443 | TCP | HTTPS | Website aman (SSL/TLS) |
| 3389 | TCP | RDP | Remote Desktop Windows |
| 53 | UDP/TCP | DNS | Menerjemahkan domain ke IP |
| 25 | TCP | SMTP | Kirim email |

#### Protocol (Protokol)

> **Analogi:** Bahasa yang dipakai untuk berkomunikasi. Ada bahasa formal (TCP) dan bahasa santai kilat (UDP).

Dua protokol utama:

| Protocol | Singkatan | Sifat | Contoh Penggunaan |
|---|---|---|---|
| **TCP** | Transmission Control Protocol | Handal, ada konfirmasi pengiriman | Browsing web, transfer file, SSH, email |
| **UDP** | User Datagram Protocol | Cepat, tanpa konfirmasi | Streaming video, game online, DNS query |
| **ICMP** | Internet Control Message Protocol | Diagnostik jaringan | `ping` command |

---

### 2.2 Apa itu Network Interface (NIC)?

**NIC = Network Interface Card = Kartu Jaringan**

> **Analogi:** Pintu masuk/keluar dari sebuah rumah. Sebuah rumah bisa punya pintu depan (untuk tamu), pintu belakang (untuk sampah), pintu garasi (untuk mobil). Setiap pintu = satu NIC.

Satu komputer bisa punya BANYAK network interface:

| Nama Interface | Biasanya untuk | Contoh di Linux |
|---|---|---|
| `eth0`, `enp0s3` | Kabel LAN (Ethernet) | Server yang dicolok kabel jaringan |
| `wlan0`, `wifi0` | WiFi / Nirkabel | Laptop, HP, WSL2 dengan WiFi |
| `lo` | Loopback (internal) | Komunikasi perangkat dengan dirinya sendiri (127.0.0.1) |
| `docker0`, `br-xxx` | Docker / Container Bridge | Untuk komunikasi antar container Docker |

**Cara melihat interface di Linux:**
```bash
ip addr show
# atau singkatnya:
ip a
```

Contoh output:
```
1: lo: <LOOPBACK> inet 127.0.0.1/8          # Interface loopback
2: eth0: <BROADCAST> inet 10.0.2.15/24      # Interface kabel LAN
3: wlan0: <BROADCAST> inet 192.168.1.100/24 # Interface WiFi
```

> 🎯 **Peran NIC dalam SAGEDRAL-ML:**  
> SAGEDRAL-ML akan "mendengarkan" trafik di **satu interface pilihan** Anda melalui fitur `promiscuous mode` (mode mendengarkan semua trafik, bukan hanya yang ditujukan ke IP dirinya).

---

### 2.3 Apa itu Packet dan Flow?

#### Packet (Paket Data)

> **Analogi:** Satu amplop surat. Setiap amplop punya: alamat pengirim (src IP), alamat tujuan (dst IP), nomor kamar tujuan (dst port), isi surat (payload/data).

Sebuah halaman web sederhana bisa terdiri dari RATUSAN packet yang dikirim bolak-balik.

Struktur packet TCP sederhana:
```
+------------------+------------------+------------------+
|  Header IP       |  Header TCP      |  Data / Payload  |
|  Src: 1.2.3.4    |  Src Port: 54321 |  <isi website /  |
|  Dst: 5.6.7.8    |  Dst Port: 443   |   request API>   |
+------------------+------------------+------------------+
```

#### Flow (Aliran Data)

> **Analogi:** Seluruh percakapan surat-menyurat antara si A dan si B tentang satu topik yang sama dalam periode tertentu. Misal: semua surat dari "A ke B tentang tagihan listrik bulan Juli" = 1 flow.

Satu **flow** didefinisikan oleh **5-Tuple** (5 identitas):

| # | Nama | Contoh | Keterangan |
|---|---|---|---|
| 1 | `src_ip` | `192.168.1.100` | Alamat IP pengirim |
| 2 | `dst_ip` | `104.18.25.43` | Alamat IP tujuan |
| 3 | `src_port` | `54321` | Port pengirim (random) |
| 4 | `dst_port` | `443` | Port tujuan (HTTPS) |
| 5 | `protocol` | `6` (=TCP) | Protokol: 6=TCP, 17=UDP, 1=ICMP |

Semua packet yang punya 5-Tuple **SAMA** = masuk ke **flow yang SAMA**.

Contoh:
- Laptop Anda `192.168.1.100:54321` buka website `google.com:443` via TCP → **FLOW A**
- Laptop Anda `192.168.1.100:54322` buka tab baru ke `google.com:443` via TCP → **FLOW B (berbeda karena src_port beda)**

> 🎯 **Peran Flow dalam SAGEDRAL-ML:**  
> SAGEDRAL-ML TIDAK mendeteksi ancaman per-packet (terlalu noise). Ia mengumpulkan packet menjadi FLOW, lalu menghitung 28 statistik dari flow tersebut (rata-rata panjang packet, jumlah flag SYN, dll), lalu memasukkannya ke model ML.

---

### 2.4 Apa itu Gateway / Router?

> **Analogi:** **Pos keci / kantor pos kelurahan** yang menjadi jalan SATU-SATUNYA keluar-masuk dari lingkungan perumahan (jaringan lokal) ke jalan raya nasional (internet).

```
[Internet Publik]
       |
       v
+------------------+        <- Ini GATEWAY / ROUTER
|  Router WiFi     |
|  IP: 192.168.1.1 |
+------------------+
    |         |
    v         v
[Laptop]    [Printer]
  .100        .50
```

Fungsi Gateway:
1. **Routing**: Meneruskan paket dari jaringan lokal ke internet, dan sebaliknya
2. **NAT (Network Address Translation)**: Menerjemahkan IP privat lokal ke IP publik saat keluar internet, dan sebaliknya saat paket kembali
3. **Firewall**: Dasar-dasar pemfilteran (port forwarding, dll)

> 🎯 **Peran Gateway dalam SAGEDRAL-ML:**  
> SAGEDRAL-ML PALING BAGUS ditempatkan di **mesin yang menjadi GATEWAY**. Karena di sanalah SEMUA trafik keluar-masuk pasti lewat. Tidak ada trafik yang lolos tanpa dicek.

---

### 2.5 Apa itu Firewall?

> **Analogi:** **Satpam gedung** yang memeriksa setiap orang yang keluar-masuk gedung berdasarkan **aturan**. Misal: "tamu hanya boleh lewat pintu lobby, pekerja boleh lewat pintu belakang, barang berbahaya dilarang masuk".

Dua jenis firewall:
1. **Stateless / Simple**: Cek hanya berdasarkan IP/Port saja (contoh: "blokir IP 1.2.3.4")
2. **Stateful / Modern**: Bisa memahami konteks koneksi (contoh: "izinkan jawaban dari website yang user buka sendiri, tapi blokir koneksi masuk yang tidak diminta")

SAGEDRAL-ML menggunakan **nftables / iptables** (firewall bawaan Linux) untuk memblokir IP secara otomatis:

```bash
# SAGEDRAL otomatis menjalankan perintah seperti ini ketika ada serangan:
nft add element inet sagedral blocklist { 192.168.1.200 }
# Artinya: Masukkan IP 192.168.1.200 ke daftar hitam, DROP semua packet dari/ke IP itu
```

---

### 2.6 Apa itu IDS, IPS, dan NIDPS?

| Akronim | Kepanjangan | Analogi | Bisa Memblokir? |
|---|---|---|---|
| **IDS** | Intrusion Detection System | **CCTV** / kamera pengawas | ❌ Hanya melihat & mencatat, memberi alarm |
| **IPS** | Intrusion Prevention System | **Satpam yang aktif mengamankan** | ✅ Bisa menahan / memblokir |
| **NIDPS** | Network IDS + IPS | **CCTV + Satpam aktif bekerja sama** | ✅ Deteksi CEGAH real-time |

SAGEDRAL-ML adalah **NIDPS** lengkap:
1. **Deteksi (IDS)**: Signature Engine + LightGBM ML Engine mendeteksi ancaman
2. **Pencegahan (IPS)**: Jika dipastikan ancaman → IPS Module memblokir IP penyerang via nftables/iptables

---

## 3. Arsitektur SAGEDRAL-ML secara Sederhana

---

### 3.1 9 Komponen Utama SAGEDRAL-ML

Bayangkan SAGEDRAL-ML sebagai **pabrik pengolahan keamanan** dengan 9 stasiun kerja berurutan:

```
  PACKET MASUK
      |
      v
  [1] CAPTURE MODULE      <-- Tukang foto, memotret setiap kendaraan
      |  (Scapy Sniffer)
      |  packet_queue
      v
  [2] FEATURE EXTRACTION  <-- Petugas administrasi, mengelompokkan kendaraan menjadi rombongan (flow)
      |  (FlowAggregator)     lalu mengisi form statistik 28 kolom
      |  flow_queue
      v
  [3] SIGNATURE ENGINE    <-- Polisi yang punya daftar "mobil paling dicari"
      |  (Rule-based)         Langsung menahan jika cocok dengan daftar hitam
      |  sig_result
      v
  [4] ML ENGINE             <-- Detektif AI, melihat pola perilaku tidak biasa
      |  (LightGBM)            "Hmm, orang ini keliling blok 100x, potensi maling"
      |  ml_result
      v
  [5] DECISION ENGINE       <-- Kepala kantor, memutuskan: "tahan?" "lapor?" "lepas?"
      |  (Scoring + Threshold)
      |  decision
      v
  [6] IPS RESPONSE MODULE   <-- Petugas security lapangan, eksekusi: blokir pintu!
      |  (nftables/iptables)
      |  alert_event
      v
  [7] DATABASE SQLite       <-- Buku catatan kejadian, semua disimpan
      |
      v
  [8] FastAPI BACKEND       <-- Bagian humas, menyajikan data untuk dashboard
      |  REST + WebSocket
      v
  [9] REACT DASHBOARD       <-- Monitor TV besar di ruang kontrol
         (Web UI)
```

#### Detail Singkat Setiap Komponen:

| # | Komponen | File Lokasi | Tugas Utama |
|---|---|---|---|
| 1 | Capture Module | [sniffer.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/capture/sniffer.py) | Menangkap packet raw dari NIC via Scapy AsyncSniffer |
| 2 | Feature Extraction | [extractor.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/features/extractor.py) | Mengagregasi packet menjadi flow, hitung 28 fitur statistik |
| 3 | Signature Engine | [signature_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/signature_engine.py) | Deteksi pola serangan KNOWN via rule-based Python |
| 4 | ML Engine | [ml_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/ml_engine.py) | Deteksi ANOMALI dan KLASIFIKASI serangan via LightGBM |
| 5 | Decision Engine | [decision_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/decision_engine.py) | Gabung skor signature + ML, putuskan: ALLOW/ALERT/BLOCK |
| 6 | IPS Module | [response.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/ips/response.py) | Eksekusi block IP via nftables/iptables + Whitelist protection |
| 7 | Database | [models.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/models.py) | SQLite: alerts, blocked_ips, traffic_stats, config_history, signature_rules |
| 8 | Backend API | [main.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/main.py) | FastAPI: REST endpoints + WebSocket push |
| 9 | Dashboard | [App.jsx](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/dashboard/src/App.jsx) | React UI: monitoring, block manual, konfigurasi |

---

### 3.2 Diagram Alir Data End-to-End

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           JALAN RAYA / NIC                                   │
│   (Kabel LAN / WiFi, promiscuous mode ON)                                   │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │ 1000 packet/detik
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. CAPTURE MODULE (Thread 1: CaptureThread)                                 │
│    Scapy AsyncSniffer → packet_queue (max 10.000 slot)                      │
│    Setiap packet masuk ke antrian tanpa block (non-blocking = put_nowait)   │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │  Raw Packet Scapy Object
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. FEATURE EXTRACTION (Thread 2: ProcessingThread)                          │
│    FlowAggregator.process_packet(packet)                                    │
│    → Kelompokkan packet berdasarkan 5-Tuple:                                │
│      (src_ip, dst_ip, src_port, dst_port, proto)                            │
│    → Update statistik FlowRecord: packet count, bytes, TCP flags, IAT       │
│    → Cek flow selesai? (TCP FIN/RST / timeout 60s / max 1000 pkt)           │
│    → Jika selesai → flow_record.to_feature_vector() → 28 angka fitur       │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │  Feature Vector (dict 28 key)
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3 & 4. HYBRID DETECTION                                                     │
│                                                                             │
│    ┌─ Signature Engine ──────────────────────────────────────────────┐     │
│    │ Loop 7 default rules: SIG-001 s/d SIG-007                       │     │
│    │ Cocokkan flow dengan rule Python lambda                         │     │
│    │ Output: SignatureResult → signature_score (0.0 - 1.0)           │     │
│    └──────────────────────────────────────────────────────────────────┘     │
│    ┌─ ML Engine (LightGBM) ──────────────────────────────────────────┐     │
│    │ Stage 1: Anomaly Binary Model → anomaly_score (0.0 - 1.0)       │     │
│    │   Jika > 0.7 → Stage 2:                                        │     │
│    │ Stage 2: Attack Classifier → attack_class (DDoS/PortScan/dll)  │     │
│    │ Output: MLResult → anomaly_score + attack_class + confidence   │     │
│    └──────────────────────────────────────────────────────────────────┘     │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │  sig_result + ml_result
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. DECISION ENGINE                                                           │
│    Rumus Skor Akhir:                                                        │
│    final_score = (0.4 × signature_score) + (0.6 × anomaly_score)           │
│                                                                             │
│    Aturan Keputusan:                                                        │
│    ├─ Signature HIGH/CRITICAL → 🔴 ACTION: BLOCK (override threshold!)     │
│    ├─ final_score >= 0.7     → 🔴 ACTION: BLOCK                            │
│    ├─ final_score >= 0.5     → 🟡 ACTION: ALERT (catat, tidak block)      │
│    └─ lainnya                → 🟢 ACTION: ALLOW                            │
│                                                                             │
│    Deduplication: Skip alert untuk IP sama dalam 5 menit terakhir           │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │  DecisionResult (action = ALLOW/ALERT/BLOCK)
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 6. IPS RESPONSE MODULE (Jika action = BLOCK)                                │
│                                                                             │
│    CHECK WHITELIST DULU (WAJIB!)                                            │
│    ├─ IP localhost (127.0.0.1)? → SKIP BLOCK                               │
│    ├─ IP gateway default? → SKIP BLOCK                                     │
│    ├─ IP saya sendiri (semua IP lokal)? → SKIP BLOCK                      │
│    ├─ IP di whitelist config? → SKIP BLOCK                                 │
│    └─ Lainnya? → LANJUT BLOCK                                              │
│                                                                             │
│    Eksekusi via nftables (preferred) atau iptables (fallback):              │
│      nft add element inet sagedral blocklist { <src_ip> }                  │
│      (Artinya: DROP semua packet masuk/keluar untuk IP ini)                 │
│                                                                             │
│    Buat AlertEvent → masuk ke alert_queue                                   │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │  AlertEvent (UUID, src_ip, attack_type, dll)
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 7, 8, 9. PENYIMPANAN & TAMPILAN                                             │
│    ┌─ SQLite DB: INSERT INTO alerts, blocked_ips, traffic_stats          │ │
│    ├─ FastAPI: WebSocket broadcast "new_alert" ke semua client dashboard  │ │
│    └─ React Dashboard: Notifikasi toast + Update tabel alert real-time     │ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Tempat Meletakkan SAGEDRAL-ML di Jaringan

> **💡 ATURAN EMAS:** Semakin dekat SAGEDRAL dengan "titik tersempit" keluar-masuk jaringan (gateway), semakin BAIK. Karena tidak ada trafik yang lolos tanpa dicek.

---

### 4.1 Topologi 1: SAGEDRAL sebagai Gateway (Inline Mode) — PALING DIREKOMENDASIKAN

#### Gambaran Umum

Ini adalah topologi TERBAIK untuk penggunaan production. SAGEDRAL-ML terpasang di mesin yang MENJADI GATEWAY sekaligus, sehingga SEMUA trafik keluar-masuk LAN WAJIB melewati SAGEDRAL.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            ISP / INTERNET                               │
│                          IP Publik: 203.x.x.x                           │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ Kabel Fiber / ADSL
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     MODEM ISP (Bridge Mode)                              │
│  Hanya meneruskan sinyal, tidak melakukan routing/NAT                   │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ Ethernet
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│           SERVER SAGEDRAL-ML SEBAGAI GATEWAY (1 mesin)                  │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────┐      │
│  │ NIC 1: eth0 (WAN - Ke Modem)                                 │      │
│  │   IP: 203.x.x.x (IP Publik dari ISP / via DHCP ISP)          │      │
│  │   ↓ Menangkap semua trafik DARI INTERNET                     │      │
│  │                                                              │      │
│  │                    [SAGEDRAL-ML BERJALAN]                    │      │
│  │   CAPTURE → FEATURE → SIGNATURE + ML → DECISION → IPS        │      │
│  │                                                              │      │
│  │ NIC 2: eth1 (LAN - Ke Switch/WiFi Internal)                  │      │
│  │   IP: 192.168.1.1/24 (Gateway untuk semua perangkat LAN)     │      │
│  │   ↑ Menangkap semua trafik DARI LAN                          │      │
│  │                                                              │      │
│  │ Service tambahan yang harus dijalankan di mesin ini:         │      │
│  │   • NAT (iptables masquerade) → IP LAN bisa akses internet  │      │
│  │   • DHCP Server → bagi IP ke perangkat LAN                  │      │
│  │   • DNS Forwarder → cache DNS untuk LAN                     │      │
│  └──────────────────────────────────────────────────────────────┘      │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ Ethernet
                               ▼
                   ┌───────────────────────┐
                   │  Switch / AP WiFi     │
                   │  (Hub untuk LAN)      │
                   └────┬──────┬──────┬────┘
                        │      │      │
                        ▼      ▼      ▼
                   [PC1]  [Laptop]  [Printer]
                    .50      .100     .51
```

#### Kelebihan Topologi Ini
✅ **Tidak ada trafik yang lolos**: Karena inline, semua packet WAN ↔ LAN harus melewati SAGEDRAL  
✅ **DIPASTIKAN bisa blokir**: IPS Module langsung memblokir di level kernel, trafik berbahaya tidak pernah sampai ke LAN  
✅ **Satu perangkat untuk semua fungsi**: Gateway + Firewall + NIDPS dalam 1 mesin, hemat biaya  

#### Kekurangan
❌ **Single Point of Failure**: Jika mesin SAGEDRAL mati → seluruh LAN hilang koneksi internet  
❌ **Butuh 2 NIC**: Mesin harus punya minimal 2 network interface card  
❌ **Butuh konfigurasi NAT/DHCP tambahan**: Bukan sekedar install SAGEDRAL, tapi harus setup server gateway dulu  

#### Spesifikasi Hardware Minimum untuk Gateway 50 User:
| Komponen | Minimum | Rekomendasi |
|---|---|---|
| CPU | Core i3 2 Core | Core i5 4 Core |
| RAM | 4 GB | 8 GB |
| Storage | 10 GB SSD (untuk DB + logs) | 20 GB SSD |
| NIC | 2 × 1Gbps Ethernet (eth0 + eth1) | 2 × 1Gbps + 1 cadangan |
| OS | Ubuntu Server 22.04 LTS | Ubuntu Server 22.04 LTS |

---

### 4.2 Topologi 2: SAGEDRAL di Samping Router (Mirror / SPAN Port)

#### Gambaran Umum

Jika Anda SUDAH punya router existing dan TIDAK INGIN mengganti fungsinya (misal router sudah disetup ISP, kompleks VPN), pakai topologi ini. SAGEDRAL hanya **mendengarkan salinan trafik** dari SPAN port / Mirror port.

```
┌──────────────────┐
│    INTERNET      │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────┐
│              ROUTER EXISTING (Jangan diganggu)           │
│  WAN: 203.x.x.x                                          │
│  LAN: 192.168.1.1/24 (Gateway normal)                    │
│                                                          │
│  Port 1 (WAN)    Port 2 (LAN)    Port 3 (MIRROR/SPAN)   │
│  Normal TX/RX     Normal TX/RX     SALINAN semua trafik │
└──┬───────────────┬────────────────┬─────────────────────┘
   │               │                │ (salinan trafik LAN+WAN)
   │               │                ▼
   │               │    ┌──────────────────────────────┐
   │               │    │   SERVER SAGEDRAL-ML         │
   │               │    │   eth0: 192.168.1.50/24      │
   │               │    │   (hanya terima salinan)     │
   │               │    │                              │
   │               │    │   MODE: IDS ONLY!            │
   │               │    │   (IPS block TIDAK EFEKTIF)  │
   │               │    └──────────────────────────────┘
   │               │
   ▼               ▼
   [ Switch / AP WiFi LAN ]
```

#### Cara Kerja SPAN/Mirror Port
- Port khusus di managed switch/router yang **menyalin 100% trafik** dari port lain (atau semua port/VLAN) ke satu port tujuan
- SAGEDRAL terhubung ke port mirror ini, menerima salinan semua packet
- Mirip CCTV: Hanya melihat, tidak bisa menghentikan orang lewat

#### Kelebihan
✅ **Tidak mengganggu jaringan existing**: Router tetap jalan normal, jika SAGEDRAL down tidak pengaruh  
✅ **Setup cepat**: Tidak perlu reconfigure seluruh gateway  
✅ **Cocok untuk organisasi yang sudah punya infrastruktur matang**  

#### Kekurangan — PENTING!
⚠️ **IPS / BLOCK MODE KURANG EFEKTIF**  
Karena SAGEDRAL hanya menerima **salinan** trafik. Packet ASLI sudah terlanjur masuk ke LAN sebelum SAGEDRAL sempat memutuskan untuk memblokir. Ada jeda waktu, dan block di mesin SAGEDRAL tidak menghentikan packet yang sudah lewat di router.

> **Solusi jika ingin tetap IPS di topologi ini:** Aktifkan integrasi API SAGEDRAL dengan router existing. Setiap SAGEDRAL mendeteksi ancaman, ia mengirim perintah REST API ke router untuk menambahkan rule block. Tapi ini perlu pengembangan custom (tidak include di v1.0).

#### Kapan Memakai Ini?
- Jika gateway adalah perangkat proprietary (Mikrotik, Cisco, Fortinet) yang tidak bisa install SAGEDRAL
- Jika bisnis TIDAK BOLEH downtime (bank, rumah sakit) — tidak mau sentuh existing gateway
- Jika tujuan utamanya **MONITORING** (IDS), bukan pencegahan (IPS)

---

### 4.3 Topologi 3: SAGEDRAL sebagai Host IDS di Server Tunggal

#### Gambaran Umum

Jika Anda hanya punya **SATU SERVER PENTING** (misal server web e-commerce, database server), Anda bisa install SAGEDRAL langsung di mesin itu untuk memproteksi dirinya sendiri.

```
┌──────────────────┐
│    INTERNET      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Firewall / NAT  │  (Misal: Cloudflare / AWS Security Group / Mikrotik)
└────────┬─────────┘
         │
         ▼
┌────────────────────────────────────────────────────────────┐
│              SERVER WEB / DATABASE (HOST)                  │
│  OS: Ubuntu 22.04                                          │
│  Public IP: 103.x.x.x (atau IP privat dari NAT)            │
│  eth0 / ens5: Network Interface Utama                      │
│                                                            │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Aplikasi: Nginx + PHP-FPM / PostgreSQL / Docker   │    │
│  └────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────┐    │
│  │  SAGEDRAL-ML (installed via pip)                    │    │
│  │  capture.interface = "eth0"                         │    │
│  │  CAPTURE trafik ke/dari server ini SAJA             │    │
│  │  IPS block langsung di host firewall                │    │
│  └────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────┘
```

#### Kelebihan
✅ **Proteksi spesifik per host**: Setiap server bisa punya policy sendiri  
✅ **Ringan**: Tidak perlu trafik jaringan penuh, hanya trafik host ini  
✅ **IPS efektif**: Block langsung di host itu sendiri  

#### Kekurangan
❌ **Hanya proteksi host ini saja**: Jika ada server lain, harus install SAGEDRAL di masing-masing  
❌ **Sumber daya terbagi**: SAGEDRAL menggunakan RAM/CPU dari server aplikasi  

#### Konfigurasi Capture Interface:
```toml
[capture]
interface = "eth0"       # Interface utama server ini
promiscuous = true
# Bisa tambah BPF filter untuk hanya trafik penting:
# bpf_filter = "tcp port 80 or tcp port 443 or tcp port 22"
```

---

### 4.4 Topologi 4: SAGEDRAL di Lab / Testing WSL2 (Untuk Belajar)

#### Gambaran Umum

Untuk Anda yang baru belajar dan ingin mencoba SAGEDRAL di LAPTOP SENDIRI tanpa beli server tambahan.

```
┌────────────────────────────────────────────────────────────────────┐
│  LAPTOP HOST WINDOWS 11 (Mesin fisik Anda)                         │
│                                                                    │
│  Host IP WiFi/LAN: 192.168.1.100 (via WiFi card fisik)            │
│                                                                    │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │  WSL2 (Ubuntu 22.04 dalam Windows)                         │   │
│  │  WSL Network Mode: "mirrored" (opsi .wslconfig)            │   │
│  │                                                            │   │
│  │  Interface di WSL2:                                        │   │
│  │    • wifi0: 192.168.1.100 (mirror dari Windows WiFi card) │   │
│  │    • lo: 127.0.0.1                                         │   │
│  │                                                            │   │
│  │  SAGEDRAL-ML running:                                      │   │
│  │    capture.interface = ""   (auto-detect wifi0)           │   │
│  │    Dashboard: http://localhost:8000 (dari Windows browser) │   │
│  │                                                            │   │
│  │  ⚠️  LIMITASI WSL2 UNTUK TESTING:                         │   │
│  │    • AF_PACKET capture tidak selalu menangkap semua trafik│   │
│  │    • Gunakan inject_flow_simulator.py untuk inject flow   │   │
│  │    • Sniffer internal kadang tidak lihat trafik loopback  │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                    │
│  Windows Browser (Chrome/Edge):                                    │
│    http://localhost:8000 → Dashboard SAGEDRAL ✅                   │
└────────────────────────────────────────────────────────────────────┘
```

#### Setting .wslconfig Untuk Mirror Mode (PENTING!)
Buat/Edit file `C:\Users\<Anda>\.wslconfig`:
```ini
[wsl2]
networkingMode=mirrored
dnsTunneling=true
firewall=true
autoProxy=true
```

> **💡 CATATAN:** Di WSL2, untuk benar-benar menguji pipeline deteksi tanpa harus kirim packet keluar nyata, gunakan **Inject Flow Simulator** (Script internal yang langsung memasukkan FlowRecord tiruan ke flow_queue tanpa melewati sniffer).

---

## 5. Contoh Kasus Implementasi Langkah demi Langkah

---

### 5.1 Kasus A: Kantor Kecil (10-50 Karyawan) sebagai Gateway

#### Latar Belakang
- Perusahaan jasa dengan 30 karyawan
- Jaringan: 1 WiFi Router + 1 Switch 24 Port + Koneksi Fiber 100 Mbps
- Masalah: Sering ada brute force SSH ke server internal, pernah kena SYN flood dari internet
- Budget terbatas untuk security appliance (Fortinet harganya mahal)

#### Rencana Topologi
Gunakan **Topologi 1: SAGEDRAL sebagai Gateway Inline**.

#### Hardware yang Dibutuhkan
| Item | Spesifikasi | Estimasi Harga (IDR) |
|---|---|---|
| Mini PC Industrial | Core i5-10310U, 8GB RAM, 256GB SSD, 2 x LAN Port | 3.5 - 5 juta |
| 2 Kabel LAN CAT6 | 1 meter untuk Modem→PC, 1 meter PC→Switch | 100 ribu |
| Total | | ~5.1 juta |

#### Langkah Implementasi

##### Langkah 1: Install Ubuntu Server 22.04 di Mini PC
- Download ISO Ubuntu Server 22.04: https://ubuntu.com/download/server
- Buat bootable USB dengan Rufus
- Boot Mini PC dari USB, install Ubuntu Server
- Saat partisi disk: pilih "Use entire disk", pilih SSD

##### Langkah 2: Setup Network (2 NIC)
Setelah install, login dan edit file Netplan:
```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Isi dengan konfigurasi 2 NIC:
```yaml
network:
  version: 2
  ethernets:
    # NIC 1: WAN (colok ke MODEM ISP)
    eth0:
      dhcp4: true              # Atau static IP dari ISP

    # NIC 2: LAN (colok ke SWITCH / AP WiFi)
    eth1:
      addresses:
        - 192.168.1.1/24      # IP Gateway untuk LAN
      dhcp4: false
```

Apply:
```bash
sudo netplan generate
sudo netplan apply
```

Verifikasi:
```bash
ip a    # Pastikan eth0 dapat IP WAN, eth1 IP 192.168.1.1
```

##### Langkah 3: Setup NAT (IP Masquerade) agar LAN bisa akses Internet
```bash
# Enable IP forwarding (wajib agar jadi router)
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Setup NAT di iptables (nftables juga bisa, iptables lebih simpel untuk pemula)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Simpan rule iptables agar survive reboot
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

##### Langkah 4: Setup DHCP Server untuk LAN
```bash
sudo apt install -y isc-dhcp-server

# Konfigurasi interface DHCP listen
echo 'INTERFACESv4="eth1"' | sudo tee /etc/default/isc-dhcp-server

# Konfigurasi pool DHCP
sudo nano /etc/dhcp/dhcpd.conf
```

Tambahkan di akhir:
```
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.200;       # IP yang akan dibagikan
    option domain-name-servers 8.8.8.8, 1.1.1.1;   # DNS Google + Cloudflare
    option routers 192.168.1.1;              # Gateway = SAGEDRAL ini
    default-lease-time 3600;                 # 1 jam
    max-lease-time 7200;                     # 2 jam
}
```

Start DHCP:
```bash
sudo systemctl restart isc-dhcp-server
sudo systemctl enable isc-dhcp-server
```

##### Langkah 5: Install SAGEDRAL-ML
```bash
# Update package
sudo apt update
sudo apt install -y python3 python3-pip python3-venv \
    libpcap-dev nftables iptables build-essential git

# Clone / copy source code
cd /opt
sudo git clone <repo-sagedral> sagedral-ml
cd sagedral-ml

# Virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Init model (WAJIB! Generate fallback model jika .pkl belum ada)
sudo .venv/bin/python -m sagedral_ml.cli model init

# Install sebagai systemd service
sudo bash scripts/install.sh
```

##### Langkah 6: Konfigurasi SAGEDRAL untuk Gateway Mode
```bash
sudo nano /etc/sagedral/config.toml
```

Setting PENTING untuk Gateway:
```toml
[capture]
interface = "eth0"          # Capture trafik dari WAN (serangan dari internet)
promiscuous = true
queue_maxsize = 10000

# Opsional: Jika Anda ingin juga capture trafik LAN (insider threat)
# Gunakan interface "any" — tapi hati-hati lebih berat CPU
# interface = "any"

[ips]
enabled = true
preferred_backend = "nftables"
auto_unblock_after = 3600     # 1 jam, bisa diperpanjang untuk repeat offender
whitelist = [
    "127.0.0.1",
    "::1",
    # TAMBAHKAN IP SERVER KRITIS DISINI:
    "192.168.1.1",             # Gateway sendiri = sudah auto-whitelist sih
    "192.168.1.10",            # Server Database Internal
    "192.168.1.20",            # Server File Internal
]

[decision]
block_threshold = 0.7          # Default oke
alert_threshold = 0.5
```

##### Langkah 7: Start Service & Verifikasi
```bash
# Start service
sudo systemctl start sagedral-ml
sudo systemctl enable sagedral-ml

# Cek status
sudo systemctl status sagedral-ml     # Harus "active (running)"

# Cek logs
sudo journalctl -u sagedral-ml -f --no-pager

# Cek CLI status
sagedral-ml status
```

##### Langkah 8: Akses Dashboard
Dari PC manapun di LAN, buka browser:
```
http://192.168.1.1:8000
```

##### Langkah 9: Test Simulasi Serangan (dari PC test)
Dari PC test di LAN (atau dari internet), jalankan port scan ringan:
```bash
# CATATAN: Jalankan test ini di jam tidak sibuk
# Peringatan: Hanya jalankan ke IP SAGEDRAL/Test server Anda sendiri!

# Port scan ringan dari PC test LAN (192.168.1.50):
nmap -T4 -F 192.168.1.1
# atau:
sudo nmap -sS 192.168.1.1
```

Setelah ~1 menit, cek Dashboard di halaman Alerts. Seharusnya muncul alert "Port Scan (SYN)" dengan severity MEDIUM.

---

### 5.2 Kasus B: Melindungi Server Web Publik

#### Latar Belakang
- 1 VPS Cloud (contoh: AWS EC2 / DigitalOcean) dengan Public IP
- Menjalankan Website + API (Nginx + Node.js/PHP)
- Butuh proteksi dari brute force SSH, SYN flood, SQL injection attempt dari internet

#### Rencana Topologi
Gunakan **Topologi 3: SAGEDRAL sebagai Host IDS**.

#### Langkah Implementasi Singkat

##### 1. Pastikan VPS memenuhi syarat
- OS: Ubuntu 22.04 LTS
- Minimal: 2 vCPU, 4GB RAM
- Firewall Cloud (AWS SG / DigitalOcean Firewall) sudah membatasi port:
  - TCP 22 (SSH)
  - TCP 80 (HTTP)
  - TCP 443 (HTTPS)
  - Semua port lain DROP di level cloud firewall

##### 2. Install SAGEDRAL
```bash
sudo apt update
sudo apt install -y python3-venv libpcap-dev nftables
cd /opt
sudo git clone <repo> sagedral-ml
cd sagedral-ml
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
sudo .venv/bin/sagedral-ml model init
sudo bash scripts/install.sh
```

##### 3. Konfigurasi Server Publik
```bash
sudo nano /etc/sagedral/config.toml
```

Setting khusus public server:
```toml
[capture]
interface = "eth0"          # Atau "ens5" untuk AWS, "eth0" untuk DigitalOcean
# Hanya capture trafik yang relevan (kurangi beban CPU):
bpf_filter = "tcp port 22 or tcp port 80 or tcp port 443"

[ips]
enabled = true
preferred_backend = "nftables"
auto_unblock_after = 86400     # 24 JAM untuk server publik (brute force attacker terus balik)
whitelist = [
    "127.0.0.1",
    # TAMBAHKAN IP ANDA SENDIRI (rumah/kantor) AGAR TIDAK KE-BLOCK:
    "203.xxx.xxx.xxx",        # IP Publik rumah Anda
    "103.xxx.xxx.xxx",        # IP Kantor Anda (jika ada)
]

[decision]
block_threshold = 0.65         # Agak sensitif untuk publik server
```

##### 4. Test Brute Force SSH (Dari IP TIDAK di whitelist)
```bash
# DARI IP LUAR (contoh HP pakai data seluler, BUKAN dari whitelist)
# Gunakan Hydra atau script untuk simulasi login SSH gagal:
for i in {1..100}; do
    ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no userwrong@<IP_SERVER> 2>/dev/null
done
```

Setelah 50 koneksi gagal, SAGEDRAL akan mendeteksi SIG-005 (Brute Force SSH) → severity HIGH → **Action: BLOCK**. IP HP Anda akan terblokir selama 24 jam.

> **💡 TIP SELAMAT:** Selalu tambahkan **IP rumah/kantor Anda sendiri ke whitelist** sebelum mengaktifkan IPS. Jangan sampai Anda sendiri ke-lockout dari server!

---

### 5.3 Kasus C: Lab Belajar di Laptop dengan WSL2

#### Latar Belakang
- Pemula ingin belajar NIDPS tanpa beli hardware
- Punya laptop Windows 11 + WSL2 terinstall

#### Langkah Implementasi

##### 1. Enable WSL2 Mirror Mode
Buka PowerShell (Administrator):
```powershell
# Jika belum enable WSL:
wsl --install -d Ubuntu-22.04

# Setup .wslconfig untuk mirror mode
notepad.exe $env:USERPROFILE\.wslconfig
```

Isi:
```ini
[wsl2]
networkingMode=mirrored
dnsTunneling=true
firewall=true
autoProxy=true
```

Shutdown WSL:
```powershell
wsl --shutdown
```

##### 2. Masuk WSL Ubuntu 22.04
```bash
# Buka WSL Ubuntu dari Start Menu

# Update
sudo apt update
sudo apt install -y python3 python3-pip python3-venv \
    libpcap-dev nftables iptables build-essential git curl

# Cek interface (pastikan wifi0 ada)
ip a
```

##### 3. Install SAGEDRAL
```bash
cd ~
git clone <repo> sagedral-ml
cd sagedral-ml

python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Init model
.venv/bin/python -m sagedral_ml.cli model init
```

##### 4. Jalankan SELFTEST Capture (Wajib untuk WSL2)
```bash
sudo .venv/bin/python -m sagedral_ml.cli selftest capture
```

Ini akan menguji apakah sniffer bisa menangkap packet. Output yang bagus:
```
HASIL: Packet COUNT tertangkap per interface:
  Interface         Packets  Status
  wifi0                 75   ✅ CAPTURE OK (>20)
  any                   75   ✅ CAPTURE OK (>20)

[REKOMENDASI] capture.interface = wifi0
```

Jika hasilnya 0 atau <20:
> Pakai `inject_flow_simulator.py` untuk testing pipeline tanpa capture real.

##### 5. Konfigurasi Minimal
```bash
# Generate config template
mkdir -p ~/.config/sagedral
python -m sagedral_ml.cli config template > ~/.config/sagedral/config.toml
```

Edit:
```toml
[capture]
interface = "wifi0"      # Dari hasil selftest tadi

[ips]
enabled = true
preferred_backend = "nftables"
auto_unblock_after = 120    # 2 menit saja untuk belajar, tidak perlu lama
```

##### 6. Start SAGEDRAL di Mode Dev
```bash
# 2 Tab terminal (atau pakai screen/tmux)

# Tab 1: Jalankan server (tanpa capture untuk lihat dashboard dulu)
source .venv/bin/activate
sudo .venv/bin/python -m sagedral_ml.main --no-capture
# Buka di Windows browser: http://localhost:8000
# Jalanin seed demo untuk lihat data:
# (buka Tab 2 baru)
source .venv/bin/activate
python -m scripts.seed_demo
```

Kembali ke browser → Dashboard sudah terisi data demo!

##### 7. Uji Simulasi Serangan WSL Friendly
Gunakan script testing yang sudah disiapkan di `scripts/testing/`:
```bash
# Simulasi SYN Flood (dengan spoof src IP agar tidak ke-block sendiri)
sudo .venv/bin/python scripts/testing/spoofed_syn_flood.py

# Tunggu 30 detik, cek halaman Alerts → Seharusnya ada alert SYN Flood!
```

---

## 6. Panduan Konfigurasi per Topologi

---

### 6.1 Konfigurasi Dasar: Config.toml

SAGEDRAL-ML dikonfigurasi melalui file **TOML** (sederhana, mirip .ini).

Lokasi file config (berurutan prioritas):
1. Path custom via environment variable / argumen
2. `~/.config/sagedral/config.toml` (user level)
3. `/etc/sagedral/config.toml` (system level, jika install service)

#### Isian Default Lengkap

```toml
# ============================================================
# SAGEDRAL-ML KONFIGURASI LENGKAP (untuk pemula)
# Setiap baris ada PENJELASAN, jangan asal copy-paste!
# ============================================================

[general]
# Level logging: DEBUG (banyak detail) → INFO (normal) → WARNING → ERROR → CRITICAL
log_level = "INFO"
# Tempat menyimpan file log (untuk troubleshooting nanti)
log_file = "/var/log/sagedral-ml.log"
# Folder data: model .pkl, database .db, temp files
data_dir = "/var/lib/sagedral-ml"

# ============================================================
# CAPTURE SETTING (Bagian terpenting untuk pemula!)
# ============================================================
[capture]
# interface: NAMA NIC yang akan di-"sniff" / didengarkan.
#   - "" (kosong string) = AUTO-DETECT (RECOMMENDED untuk pemula)
#   - Manual: isi dengan nama interface dari `ip a`
#     Contoh nilai: "eth0", "eth1", "wlan0", "wifi0", "any"
interface = ""

# bpf_filter: Filter BPF (Bahasa tcpdump) untuk hanya capture trafik tertentu.
#   - "" (kosong) = Capture SEMUA packet di interface.
#   - Untuk server spesifik, filter lebih bagus: hemat CPU + RAM.
# Contoh untuk web server:
#   bpf_filter = "tcp port 80 or tcp port 443 or tcp port 22"
# Contoh hanya trafik TCP:
#   bpf_filter = "tcp"
bpf_filter = ""

# promiscuous: Mode "mendengarkan SEMUA trafik", bukan hanya yang ditujukan ke IP sendiri.
#   - true = WAJIB untuk mode GATEWAY dan mode MIRROR (SPAN port).
#   - false = Hanya dengarkan trafik yang ditujukan ke IP host ini.
promiscuous = true

# queue_maxsize: Jumlah maksimal packet yang diantre sebelum di-drop (lindungi RAM).
# Untuk trafik 1Gbps normal, 10000 sudah cukup.
queue_maxsize = 10000

# ============================================================
# FEATURE EXTRACTION (Gabung packet jadi flow)
# ============================================================
[feature_extraction]
# flow_timeout: Detik. Jika tidak ada packet baru dalam waktu ini, flow dianggap SELESAI
#   dan masuk ke tahap detection. Default 60 detik cukup untuk hampir semua kasus.
flow_timeout = 60

# max_packets_per_flow: Maksimal packet dalam 1 flow sebelum dipaksa selesai.
# Melindungi dari flow gigabyte super panjang yang bikin RAM penuh.
max_packets_per_flow = 1000

# ============================================================
# SIGNATURE ENGINE (Rule-based deteksi pola KNOWN)
# ============================================================
[signature]
# enabled: Matikan signature engine jika ingin HANYA pakai ML.
enabled = true

# custom_rules_file: Path ke file Python isinya rules tambahan.
# Biarkan kosong jika belum punya.
custom_rules_file = ""

# disabled_rules: List ID rule yang mau dimatikan sementara.
# Contoh: ["SIG-002"] untuk matikan rule Port Scan jika banyak false positive
disabled_rules = []

# ============================================================
# ML ENGINE (LightGBM Anomaly + Classifier)
# ============================================================
[ml]
# enabled: Matikan ML engine jika hanya ingin pakai signature saja (mode legacy).
enabled = true

# anomaly_threshold: Ambang batas (0.0 - 1.0) untuk menyatakan sebuah flow "anomali".
#   - Semakin KECIL → Semakin SENSITIF → Semakin banyak alert (lebih false positive)
#   - Semakin BESAR → Semakin KURANG sensitif → Mungkin ada ancaman lolos
# Default 0.7 adalah sweet spot.
anomaly_threshold = 0.7

# classifier_threshold: Minimal confidence (0.0 - 1.0) agar attack class diterima.
# Jika di bawah ini, attack_class = "UNKNOWN_ANOMALY"
classifier_threshold = 0.6

# model_dir: Lokasi folder penyimpanan file model .pkl
model_dir = "/var/lib/sagedral-ml/models"

# retrain_on_startup: Retrain model OTOMATIS setiap service start?
# JANGAN aktifkan di production (start jadi lambat!). Gunakan CLI manual: sagedral-ml train
retrain_on_startup = false

# ============================================================
# DECISION ENGINE (Rumus final score + aturan block/alert)
# ============================================================
[decision]
# alert_threshold: Score >= ini → BUAT ALERT (catat di DB + notifikasi ke dashboard),
# tapi TIDAK block IP. Digunakan untuk investigasi.
alert_threshold = 0.5

# block_threshold: Score >= ini → BLOKIR IP penyerang (jika IPS enabled).
# HARUS LEBIH BESAR dari alert_threshold.
block_threshold = 0.7

# weight_signature + weight_ml: Bobot dalam perhitungan final_score.
# Jumlah keduanya = 1.0 secara logika (tapi system normalize otomatis).
# Default: ML 60% lebih dipercaya daripada Signature 40%.
weight_signature = 0.4
weight_ml = 0.6

# dedup_window: Detik. Untuk IP yang sama, dalam waktu ini JANGAN kirim alert berulang.
# Hindari spam alert jika satu IP melakukan 1000 serangan sekaligus.
dedup_window = 300

# ============================================================
# IPS RESPONSE MODULE (Firewall Block Action)
# ============================================================
[ips]
# enabled: Matikan semua block action. Menjadi mode IDS-only (CCTV).
# Biasanya ini di-set false saat periode awal testing / belajar.
enabled = true

# preferred_backend: "nftables" (modern, recommended) atau "iptables" (legacy).
preferred_backend = "nftables"

# auto_unblock_after: Detik. IP yang di-block otomatis dilepas kembali setelah ini.
# 0 (nol) = BLOCK PERMANEN (sampe manual unblock).
# Untuk pemula: 3600 (1 jam) atau 1800 (30 menit) agar tidak bingung kenapa IP terblokir selamanya.
auto_unblock_after = 3600

# whitelist: DAFTAR IP YANG TIDAK BOLEH DIBLOKIR SEKALI PUN!
# WAJIB isi IP penting di sini.
whitelist = [
    "127.0.0.1",        # localhost sendiri (HARDCODED di source, tapi tulis ulang untuk dokumentasi)
    "::1",              # localhost IPv6
    # "192.168.1.0/24",  # (Opsional) Seluruh subnet LAN, jika Anda percaya LAN 100%.
]

# ============================================================
# API & DASHBOARD (FastAPI + React)
# ============================================================
[api]
# host: "0.0.0.0" = Bisa diakses dari perangkat manapun di jaringan.
#       "127.0.0.1" = Hanya bisa diakses dari mesin itu sendiri (paling aman).
host = "0.0.0.0"

# port: Port dashboard & REST API. Pastikan tidak bentrok dengan service lain.
port = 8000

# cors_origins: Daftar asal URL yang boleh akses API via browser (CORS policy).
# Default untuk Vite dev server (port 5173) dan React dev (port 3000).
cors_origins = ["http://localhost:5173", "http://localhost:3000"]

# ============================================================
# DATABASE (SQLite)
# ============================================================
[database]
# path: Lokasi file database SQLite. Default sudah cukup.
path = "/var/lib/sagedral-ml/sagedral.db"

# retention_days_alerts: Berapa hari data alert disimpan sebelum dihapus otomatis.
# Default 30 hari. Kalau harddisk besar, bisa perpanjang.
retention_days_alerts = 30

# retention_days_traffic: Berapa hari data traffic time-series disimpan.
# Data traffic cuma untuk chart, lebih cepat dihapus (hemat DB size).
retention_days_traffic = 7
```

---

### 6.2 Konfigurasi Interface untuk Gateway Mode

Di topologi Gateway Inline (Topologi 1), keputusan TERBESAR adalah **interface mana yang di-capture**:

| Opsi Capture Interface | Trafik yang Tercatat | Kapan Digunakan |
|---|---|---|
| `eth0` (WAN saja) | Semua trafik dari/ke Internet | Kebanyakan kasus, yang berbahaya = dari Internet |
| `eth1` (LAN saja) | Semua trafik dari/ke LAN | Untuk monitoring insider threat / internal attacker |
| `"any"` (semua interface) | Trafik WAN + LAN + lokal | Paling lengkap, tapi lebih berat CPU/RAM |

**REKOMENDASI untuk Pemula Gateway:**
- **Periode 0-2 minggu (observasi)**: Gunakan `interface = "any"` untuk memahami pola trafik seluruh jaringan
- **Setelah stabil**: Ubah ke `interface = "eth0"` (hanya WAN) untuk hemat resource

> **⚠️ HATI-HATI:** Jika Anda capture di `eth1` (LAN), trafik INSIDER seperti staff internal yang portscan server internal juga akan terdeteksi dan terblokir. Pastikan semua IP staff penting ada di whitelist!

---

### 6.3 Konfigurasi Whitelist Penting

**Whitelist = Daftar IP Aman yang TIDAK BOLEH DIBLOKIR SEKALI PUN**

SAGEDRAL-ML otomatis mem-whitelist 3 kategori (tidak perlu tulis manual):
1. `127.0.0.1` / `::1` → Loopback
2. **Default Gateway IP** → Router utama (deteksi otomatis via `ip route show default`)
3. **SEMUA IP lokal yang terpasang di mesin SAGEDRAL** → `ip a` scan otomatis, semua IP masuk local_ips

#### TAMBAHAN yang WAJIB Anda Tuliskan Manual di config.toml:
```toml
[ips]
whitelist = [
    # SELALU ADA
    "127.0.0.1",
    "::1",

    # ===== TAMBAHAN PENTING =====

    # 1. IP ANDA SENDIRI (rumah + kantor) - JANGAN SAMPAI KE-BLOCK saat debugging!
    "203.153.21.45",       # IP Publik rumah Indihome
    "103.14.55.10",        # IP Kantor

    # 2. SERVER INTERNAL KRITIS (DNS, DC, File Server)
    "192.168.1.10",        # DNS Server Internal
    "192.168.1.20",        # Domain Controller
    "192.168.1.30",        # NAS Backup

    # 3. VENDOR / MITRA YANG SERING AKSES (jika ada)
    "104.16.132.229",      # IP SaaS vendor payroll
    "180.214.200.5",       # IP IT Support vendor
]
```

**Cara Menambah Whitelist via Dashboard (Lebih Mudah):**
1. Buka `http://<ip-sagedral>:8000/blocked-ips`
2. Scroll ke bawah → Bagian **Whitelist**
3. Masukkan IP, klik **Add to Whitelist**
4. Selesai, tidak perlu restart service!

---

### 6.4 Konfigurasi Threshold Detection untuk Pemula

#### Konsep Threshold seperti "Alarm Kebakaran"

```
Skor 0.0 ────────────────────────────────────────── 1.0
       │               │                │               │
       └─── NORMAL ────┘─── ALERT ─────┘──── BLOCK ────┘
       │               │                │               │
      0.0       alert_threshold   block_threshold      1.0
                  (default 0.5)      (default 0.7)
```

#### Profil Konfigurasi Threshold Berdasarkan Tingkat Toleransi Risiko

| Profile | alert_threshold | block_threshold | Penjelasan | Cocok Untuk |
|---|---|---|---|---|
| **Longgar** (Pemula / Testing) | `0.6` | `0.85` | Jarang alert, jarang block. Jarang false positive, tapi mungkin ada ancaman lolos | Belajar, fase observasi awal 1-2 minggu |
| **Seimbang** (Default) | `0.5` | `0.7` | Keseimbangan terbaik antara deteksi dan false positive | Umum, kantor, production setelah tuning |
| **Ketat** (High Security) | `0.35` | `0.55` | Banyak alert, cepat block. Bisa jadi banyak false positive tapi ancaman minim lolos | Data center, server bank, sistem kritikal |
| **IDS-Only** | `0.3` | `1.0` | Semua ancaman hanya ALERT, TIDAK PERNAH BLOCK | Fase audit, mode CCTV, topologi SPAN port |

**Rekomendasi Tahapan untuk Pemula:**
1. **Minggu 1**: Profile IDS-Only → Pelajari pola trafik normal
2. **Minggu 2**: Profile Longgar → Block yang jelas-jelas attack saja
3. **Minggu 3+**: Profile Seimbang (Default) → Production-ready

---

## 7. Contoh Serangan yang Dapat Dideteksi SAGEDRAL-ML

---

### 7.1 SYN Flood (DoS)

**Apa itu?**
> Penyerang mengirimkan **ribuan SYN packet (permintaan koneksi)** TANPA pernah menyelesaikan handshake TCP (tidak kirim ACK terakhir). Target kehabisan resource karena menyimpan setengah koneksi dalam backlog queue.

**Analogi:** Orang jahat menelpon kantor Anda BERKALI-KALI, langsung tutup sebelum operator angkat telpon. Operator jadi sibuk "menunggu jawaban" telpon palsu dan tidak bisa melayani telpon asli.

**Signature Rule (SIG-001) dalam SAGEDRAL:**
```python
# Jika dalam satu flow:
#   syn_flag_count > 100   (Banyak SYN)
#   ack_flag_count < 10    (Hampir tidak ada ACK = koneksi tidak pernah selesai)
#   duration < 5 detik     (Semua terjadi sangat cepat)
# MAKA: SYN Flood terdeteksi!
```

**Apa yang akan terjadi di SAGEDRAL?**
| Komponen | Hasil |
|---|---|
| Signature Engine | SIG-001 matched, severity=HIGH, score=0.75 |
| ML Engine | anomaly_score=0.92, attack_class="DDoS" |
| Decision Engine | final_score = (0.4×0.75)+(0.6×0.92)=0.85 → action=BLOCK |
| IPS Module | IP penyerang dimasukkan ke nftables blocklist |

---

### 7.2 Port Scanning

**Apa itu?**
> Penyerang "memeriksa pintu" satu per satu: port 22 (SSH) buka tidak? Port 3389 (RDP) buka tidak? Port 8080 buka tidak? Tujuannya mencari celah / service yang bisa diserang.

**Analogi:** Maling berkeliling komplek perumahan, memeriksa setiap pintu: pintu 1 dikunci rapat, pintu 2 lupa dikunci, pintu 3 ada CCTV. Catat semuanya, rencanakan masuk lewat pintu 2.

**2 Tipe Port Scan yang Sering:**
| Tipe | Nama | Ciri di Flow |
|---|---|---|
| `-sS` | SYN Stealth Scan | Banyak SYN ke port berbeda, tapi tidak ada FIN/RST (tidak pernah selesai koneksi) |
| `-T5` | Fast Scan | Super cepat, ribuan port dalam beberapa detik |

**Signature Rule (SIG-002):**
```python
# total_fwd_packets < 3    (Hanya kirim 1-2 packet, tidak mau koneksi beneran)
# syn_flag_count >= 1      (Pasti ada SYN)
# fin_flag_count == 0      (Tidak ada FIN = tidak pernah tutup koneksi normal)
```

**Yang sering False Positive:**
- Monitoring server (Nagios/Zabbix) yang health-check port layanan
- Developer yang test koneksi database dengan `telnet` / `nc`
→ Solusi: Masukkan IP monitoring server ke whitelist, atau disable SIG-002 jika too noisy.

---

### 7.3 Brute Force SSH / RDP

**Apa itu?**
> Penyerang mencoba LOGIN BERULANG KALI dengan kombinasi username dan password berbeda. Misal coba 1000 password untuk user `admin` / `root`.

**Analogi:** Mencoba ribuan anak kunci ke gembok pintu rumah, berharap ada yang cocok.

**Signature Rules:**
- **SIG-005 SSH Brute Force**: dst_port==22 AND total_fwd_packets>50 AND duration<30 detik
- **SIG-006 RDP Brute Force**: dst_port==3389 AND total_fwd_packets>30 AND duration<60 detik

**Pencegahan Tambahan SELAIN SAGEDRAL:**
1. Gunakan **SSH Key Authentication** (bukan password login)
2. Ubah port SSH dari 22 ke port acak (misal 2222)
3. Pakai **Fail2ban** sebagai lapisan kedua (saling melengkapi SAGEDRAL)
4. Batasi IP mana yang boleh SSH via firewall cloud

---

### 7.4 UDP Flood / ICMP Flood

**Apa itu UDP Flood?**
> Ribuan UDP packet besar dikirim ke port target dengan src IP palsu (spoofed). Target menghabiskan bandwidth memprosesnya.

**Apa itu ICMP Flood (Ping Flood)?**
> Ribuan `ping` (ICMP Echo Request) dikirim ke target secara paralel. Target sibuk membalas ping sampai lambat / down.

**Signature Rules:**
- **SIG-003 ICMP Flood**: protocol==1 (ICMP) AND flow_packets_per_sec > 1000
- **SIG-007 UDP Flood**: protocol==17 (UDP) AND flow_packets_per_sec > 5000

**Catatan:** Jika jaringan Anda sehari-hari ada aplikasi UDP volume tinggi (misal VoIP/SIP, video conference WebRTC, game server), Anda mungkin perlu **menaikkan threshold** di rule SIG-007 agar tidak false positive.

---

### 7.5 Data Exfiltration (Pencurian Data)

**Apa itu?**
> Attacker yang sudah berhasil masuk ke jaringan Anda mengirim DATA BESAR (database, file rahasia) keluar ke server nya di internet.

**Ciri Khas di Flow:**
- `total_bwd_bytes` (byte keluar / dari internal ke eksternal) SANGAT BESAR > 100 MB
- Atau `down_up_ratio` sangat timpang (download/upload tidak seimbang)

**Signature Rule (SIG-004):**
```python
# total_bwd_bytes > 100_000_000   (Transfer data keluar > 100MB dalam satu flow)
# → Potensi exfiltration, beri alert MEDIUM
```

**Yang sering False Positive:**
- Karyawan upload video presentasi ke YouTube
- Backup cloud otomatis (AWS S3 sync, Google Drive)
- Video call panjang 2 jam (WebRTC)

→ Solusi: Buat **custom rule** yang mengecualikan domain cloud provider terpercaya (lewat dst IP whitelist untuk IP range AWS/Azure/GCP).

---

## 8. Cara Membaca Dashboard SAGEDRAL-ML

Dashboard dapat diakses di: `http://<IP-SAGEDRAL>:8000`

---

### 8.1 Halaman Overview: Ringkasan Umum

Ini adalah halaman pertama yang Anda lihat saat login dashboard.

```
┌──────────────────────────────────────────────────────────────────────┐
│  [STATUS BADGE: 🟢 ONLINE / 🔴 OFFLINE]  [WebSocket Connected]       │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────┐ ┌─────────┐ ┌────────────┐ ┌────────────────────┐      │
│  │ Packets │ │  Alerts │ │ Blocked IPs│ │ Threats Blocked 24h│      │
│  │ 1.2M    │ │   47    │ │    12      │ │       129          │      │
│  │ (24h)   │ │ (24h)   │ │   (aktif)  │ │                    │      │
│  └─────────┘ └─────────┘ └────────────┘ └────────────────────┘      │
│   StatsCard        x4 buah = ukuran performa terkini                 │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Traffic Chart (Line Chart Recharts)                       │      │
│  │  ░░░░░ packets_per_sec  ████████ bytes_per_sec             │      │
│  │  Sumbu Y = jumlah / Sumbu X = 5 menit terakhir             │      │
│  │  Dibuang update real-time via WebSocket setiap 5 detik     │      │
│  └────────────────────────────────────────────────────────────┘      │
│                                                                      │
│  ┌─────────────────────────┐  ┌──────────────────────────────┐       │
│  │ Recent Alerts (10 terbaru)│  │ Attack Type Pie Chart       │       │
│  │ Time | Src IP | Type     │  │ 52% DDoS                    │       │
│  │ 15:21| 1.2.3.4| DDoS     │  │ 28% PortScan                │       │
│  │ ...  | ...    | ...      │  │ 20% BruteForce              │       │
│  └─────────────────────────┘  └──────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────────┘
```

**Yang harus dicek setiap pagi oleh Network Admin Pemula:**
1. **Status Badge hijau** = system ON. Jika merah → service mati, SSH ke server cek `systemctl status sagedral-ml`
2. **Blocked IPs > 0 tapi tidak terlalu banyak** (normal 5-50 untuk kantor 50 user)
3. **Traffic Chart** = lihat spike aneh. Jika tiba-tiba packets_per_sec 100x lipat normal → WAKTU-WAKTU ada DDoS!
4. **Recent Alerts** = scroll cepat, apakah ada attack_type yang baru / tidak pernah muncul sebelumnya?

---

### 8.2 Halaman Alerts: Daftar Ancaman

URL: `/alerts`

Fitur untuk **investigasi detail** setiap ancaman:

| Kolom | Isi | Apa Artinya |
|---|---|---|
| ⏰ Time | `2026-07-25 15:21:03` | Kapan serangan terjadi |
| 📡 Src IP | `203.xx.xx.55` | IP asal penyerang → klik kanan → IP lookup untuk tahu negara/ISP |
| 🎯 Dst IP | `192.168.1.10` | IP target diserang |
| ⚔️ Attack Type | `DDoS`, `BruteForce` | Jenis serangan |
| 🚨 Severity | 🟢LOW / 🟡MEDIUM / 🔴HIGH / ⚫CRITICAL | Tingkat bahaya |
| 📊 Score | `0.85` | Final Score (bobot signature + ML) |
| ✅ Action | `BLOCKED` / `ALERTED` / `WHITELISTED` | Apa yang dilakukan SAGEDRAL |

**Cara menggunakannya (untuk pemula):**
1. Buka halaman Alerts
2. Filter **Severity = HIGH + CRITICAL** dulu (paling berbahaya)
3. Untuk setiap alert:
   - Klik row → Muncul **AlertDetailModal** (detail lengkap 28 fitur flow)
   - Jika src IP jelas attacker (misal dari negara tidak kenal, port scan acak) → Klik tombol **"Block IP Permanently"**
   - Jika src IP adalah staff Anda (false positive) → Klik **"Add IP to Whitelist"**
4. Export ke CSV setiap minggu → buat laporan untuk atasan

---

### 8.3 Halaman Blocked IPs: Daftar IP yang Diblokir

URL: `/blocked-ips`

Dua bagian utama:
1. **Tabel IP yang Diblokir**:
   - IP, alasan, waktu diblokir, waktu auto-unblock (countdown)
   - Tombol **Unblock** untuk melepas satu per satu
2. **Form Manual Block**:
   - Untuk memblokir IP secara manual (misal dari laporan tim SOC)
   - Pilih durasi: 15 menit / 1 jam / 24 jam / Permanent
3. **Daftar Whitelist**:
   - Tambah/hapus IP dari whitelist
   - Ini adalah **tempat termudah** untuk menambah whitelist, tidak perlu edit config.toml

---

### 8.4 Halaman Traffic: Analisa Trafik

URL: `/traffic`

Untuk **melihat pola normal trafik jaringan**:
- **TimeRangeSelector**: Pilih 1 jam / 6 jam / 24 jam / 7 hari terakhir
- **TrafficAreaChart**: Bandingkan trafik hari Senin vs hari Minggu (pola normal)
- **AlertsBarChart**: Jam berapa serangan PALING SERING terjadi? (biasanya jam 10 pagi - 4 sore UTC = jam kerja hacker di Eropa/US)
- **TopTalkersTable**: 10 IP paling banyak trafik / paling banyak alert

**Tips untuk Pemula:**
Setelah SAGEDRAL berjalan 1 minggu, buka halaman ini pilih **7 hari**. Pelajari pola normal:
- Jam berapa traffic puncak? (biasanya jam 9-11 pagi, 13-15 sore = karyawan kerja)
- Berapa packets_per_sec rata-rata? (misal 100-200 normal, 10000 = DDoS)
- IP mana yang jadi top talker setiap hari? (biasanya server proxy / DNS)

---

### 8.5 Halaman Settings: Pengaturan

URL: `/settings`

Semua konfigurasi config.toml BISA diubah LANGSUNG dari dashboard tanpa SSH!

Bagian yang sering diubah pemula:
1. **Detection Settings** (Paling serius diutak-atik):
   - Slider `alert_threshold` dan `block_threshold`
   - Geser slider → Lihat preview perubahan skor → Klik Save
2. **IPSSettings**:
   - Toggle `IPS Enabled` (Klik off jika Anda ingin mode IDS-only / belajar)
   - Whitelist editor (tambah IP dengan klik)
3. **SignatureRulesManager**:
   - Lihat 7 rules default SIG-001 s/d SIG-007
   - Toggle ON/OFF per-rule (misal matikan SIG-002 Port Scan jika bikin alert palsu)
   - Tambah **Custom Rule** baru (jika Anda sudah mahir Python lambda)

> **⚠️ CATATAN:** Beberapa perubahan (misal `capture.interface`) membutuhkan **restart service**. Dashboard akan menampilkan pesan: "Config updated. Requires restart for: capture.interface".

---

## 9. Perintah CLI SAGEDRAL-ML yang Sering Digunakan

Selain dashboard, SAGEDRAL punya **CLI tool** bernama `sagedral-ml` (terinstal di PATH jika install via pip / install.sh).

| Kategori | Perintah | Kegunaan |
|---|---|---|
| **Service** | `sagedral-ml status` | Cek service jalan atau tidak |
| | `sagedral-ml start --daemon` | Start service background |
| | `sagedral-ml start --no-capture` | Start tanpa capture (mode dashboard-only / demo) |
| | `sagedral-ml stop` | Stop service |
| | `sagedral-ml restart` | Restart service |
| **Config** | `sagedral-ml config show` | Tampilkan config aktif dalam JSON |
| | `sagedral-ml config template` | Cetak template config.toml default |
| | `sagedral-ml config validate` | Validasi apakah config Anda ada error |
| **IP Block** | `sagedral-ml block <IP> --duration 3600` | Manual block IP via CLI |
| | `sagedral-ml unblock <IP>` | Manual unblock IP |
| | `sagedral-ml block 1.2.3.4 --reason "Hacker dari forum"` | Block dengan alasan |
| **Alerts** | `sagedral-ml alerts list --limit 50` | Tampilkan 50 alert terbaru di terminal |
| | `sagedral-ml alerts list --limit 5` | 5 alert terbaru (cepat cek) |
| **Models** | `sagedral-ml model init` | **WAJIB JALANKAN SAAT INSTALL!** Generate model fallback jika .pkl tidak ada |
| | `sagedral-ml model init --force` | Hapus model lama, generate ulang (untuk troubleshooting) |
| | `sagedral-ml model info` | Cek info model: versi, loaded/tidak |
| **Self Test (WSL)** | `sudo sagedral-ml selftest capture` | Test apakah sniffer bisa menangkap packet di interface |
| | `sagedral-ml selftest sniffer-status` | Query live stats via API |
| **Systemd** | `sudo systemctl status sagedral-ml` | Cek status service via systemd |
| | `sudo journalctl -u sagedral-ml -f` | Live streaming log service |
| | `sudo journalctl -u sagedral-ml --since "1 hour ago"` | Lihat log 1 jam terakhir |

---

## 10. Troubleshooting Umum untuk Pemula

---

### 10.1 SAGEDRAL tidak menangkap paket

**Gejala:** `packets_captured` di status selalu 0, tidak ada alert sama sekali.

#### Step-by-Step Perbaiki:

##### Step 1: Jalankan SELFTEST Capture (Paling cepat)
```bash
sudo sagedral-ml selftest capture
```

##### Step 2: Cek interface benar
```bash
# Lihat semua interface
ip a

# Cek interface mana yang UP dan punya IP
# Pastikan config.toml capture.interface = nama interface yang benar

# Misal interface aktif = wifi0
# Edit config.toml:
#   [capture]
#   interface = "wifi0"
```

##### Step 3: Cek permission root
Scapy butuh **root** untuk promiscuous mode! Pastikan Anda start service dengan `sudo` atau systemd berjalan sebagai root.

```bash
# Test manual: Jalankan tcpdump di interface selama 10 detik
sudo tcpdump -ni wifi0 -c 50
# Jika tcpdump TIDAK MENDAPATKAN packet apapun juga = masalah di driver / WSL,
# bukan masalah SAGEDRAL.
```

##### Step 4: Jika WSL2 Mirror Mode
Jika di WSL2 dan tcpdump juga 0 packet:
> Ini adalah LIMITASI WSL kernel yang diketahui. Gunakan **Inject Flow Simulator** untuk testing pipeline detection tanpa capture:
> ```bash
> python3 scripts/testing/inject_flow_simulator.py
> ```

---

### 10.2 IP saya sendiri terblokir! 😱

**Gejala:** Anda tidak bisa SSH / akses dashboard dari IP kantor/rumah sendiri.

#### Penyebab:
Anda melakukan sesuatu yang dianggap SAGEDRAL sebagai attack (misal test port scan ke server, coba login SSH salah password 10x), dan IP Anda TIDAK ada di whitelist.

#### Cara Memperbaiki (Urutan Prioritas):

##### Opsi 1: Dari mesin lokal (konsol fisik / VNC / cloud console)
```bash
# Masuk ke server melalui console / serial / VNC (bukan SSH, karena SSH Anda terblokir!)

# 1. Lihat daftar IP yang diblokir oleh nftables
sudo nft list set inet sagedral blocklist

# 2. Keluarkan IP Anda dari blocklist
sudo nft delete element inet sagedral blocklist { 203.153.21.45 }
# Ganti 203.153.21.45 dengan IP rumah Anda!

# 3. SEGERA tambahkan ke whitelist di config.toml agar tidak terulang
sudo nano /etc/sagedral/config.toml
#   [ips]
#   whitelist = [
#       "127.0.0.1",
#       "::1",
#       "203.153.21.45",   # <= TAMBAHKAN BARIS INI
#   ]

# 4. Restart service
sudo systemctl restart sagedral-ml
```

##### Opsi 2: Tunggu Auto-Unblock (jika sempat)
Jika Anda set `auto_unblock_after = 3600` (1 jam), Anda tinggal menunggu 1 jam maka IP akan otomatis dilepas. **TAPI:** ini hanya berlaku untuk block **yang belum permanent**.

---

### 10.3 Dashboard tidak bisa diakses

**Gejala:** Buka `http://<ip>:8000` → `ERR_CONNECTION_REFUSED` atau timeout.

#### Check List:

1. **Service jalan?**
   ```bash
   sagedral-ml status
   # Jika STOPPED:
   sudo systemctl start sagedral-ml
   ```

2. **Port 8000 sedang Listen?**
   ```bash
   sudo netstat -tulpn | grep 8000
   # Expected output:
   # tcp  0  0 0.0.0.0:8000  0.0.0.0:*  LISTEN  12345/python3
   #
   # Jika KOSONG = uvicorn tidak jalan → cek journalctl log error
   ```

3. **Firewall OS (iptables/nftables) membuka port 8000?**
   ```bash
   # Test dari mesin SAGEDRAL sendiri (localhost):
   curl http://127.0.0.1:8000/api/v1/status
   # Jika ini BERHASIL tapi dari PC lain GAGAL = masalah firewall OS

   # Buka port 8000 di iptables:
   sudo iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
   sudo netfilter-persistent save
   ```

4. **Firewall Cloud membuka port 8000?**
   Jika server ini di AWS/DigitalOcean: cek Security Group / Cloud Firewall, pastikan port 8000 inbound diizinkan.

5. **API host setting?**
   Pastikan di config:
   ```toml
   [api]
   host = "0.0.0.0"      # JANGAN "127.0.0.1" jika ingin diakses dari luar mesin!
   port = 8000
   ```

---

### 10.4 Terlalu banyak alert palsu (False Positive)

**Gejala:** 50+ alert per hari, tapi setelah dicek semuanya adalah trafik normal.

#### Cara Tuning Step-by-Step:

**Langkah 1: Identifikasi pola false positive**
- Jenis attack apa yang PALING BANYAK false positive?
  - Misal: `PortScan` alert selalu dari IP `192.168.1.50` = Zabbix monitoring server
  - Misal: `Exfiltration` alert selalu dari upload backup ke S3

**Langkah 2: Whitelist IP penyebab false positive**
```bash
# Dashboard lebih mudah: /blocked-ips → Whitelist Section
# Atau CLI:
# - Di Whitelist IPS tidak otomatis matikan alert, tapi mencegah block

# Untuk IP monitoring server:
sagedral-ml block  # <- Tidak usah block, tambah ke whitelist lewat config
```

**Langkah 3: Matikan rule tertentu yang terlalu noisy**
- Jika Port Scan selalu false positive di jaringan Anda:
  - Buka Dashboard → `/settings` → Signature Rules Manager → Toggle OFF `SIG-002`
  - Atau edit config: `disabled_rules = ["SIG-002"]`

**Langkah 4: Naikkan threshold**
Ubah profile dari **Seimbang** ke **Longgar**:
```toml
[decision]
alert_threshold = 0.6    # Dari 0.5 naik jadi 0.6
block_threshold = 0.85   # Dari 0.7 naik jadi 0.85
```

**Langkah 5: Tambah BPF filter agar hanya trafik penting**
Di gateway, misal trafik internal staff 90% adalah trafik antar kantor yang normal:
```toml
[capture]
# Hanya capture trafik ke/dari server publik / penting:
bpf_filter = "host 192.168.1.10 or host 192.168.1.20 or tcp port 22"
```

---

## 11. Glosarium Istilah Penting

Daftar istilah yang sering muncul di dokumentasi dan dashboard SAGEDRAL-ML:

| Istilah | Arti Singkat |
|---|---|
| **NIC** | Network Interface Card = Kartu jaringan (ethernet port / wifi) |
| **IP Address** | Alamat unik perangkat di jaringan (contoh: 192.168.1.1) |
| **Port** | Nomor "kamar" dalam satu IP, membedakan layanan (SSH=22, HTTP=80) |
| **Protocol** | Bahasa komunikasi: TCP (handal) / UDP (cepat) / ICMP (ping) |
| **5-Tuple** | (src_ip, dst_ip, src_port, dst_port, proto) = kunci unik 1 flow |
| **Packet** | Satuan data kecil yang dikirim melalui jaringan (satu "amplop") |
| **Flow** | Kumpulan packet dengan 5-tuple sama (satu "percakapan") |
| **Gateway** | Router = perangkat jalan satu-satunya keluar ke internet |
| **NAT** | Penerjemah IP privat → IP publik (fitur router) |
| **Firewall** | Satpam jaringan, filter packet berdasarkan aturan |
| **IDS** | Intrusion Detection System = Hanya mendeteksi & catat |
| **IPS** | Intrusion Prevention System = Deteksi + BISA memblokir |
| **NIDPS** | Network IDS + IPS = SAGEDRAL-ML adalah ini! |
| **nftables** | Firewall modern Linux (lebih bagus dari iptables) |
| **iptables** | Firewall legacy Linux (banyak dipakai, tapi deprecated) |
| **BPF Filter** | Filter Bahasa tcpdump untuk memilih packet yang di-capture |
| **Promiscuous Mode** | Mode NIC mendengarkan SEMUA trafik, bukan hanya untuk dirinya |
| **SPAN / Mirror Port** | Port di switch yang menyalin semua trafik ke satu port |
| **Signature** | Rule deteksi pola serangan KNOWN (rule-based Python lambda) |
| **Anomaly Detection** | Mendeteksi perilaku TIDAK NORMAL via model ML |
| **True Positive** | Alert BETUL = ini memang serangan beneran |
| **False Positive** | Alert SALAH = trafik normal tapi dianggap serangan |
| **True Negative** | Trafik normal, tidak ada alert = benar tidak alert |
| **False Negative** | Serangan nyata tapi TIDAK ADA alert = ancaman lolos |
| **Whitelist** | Daftar IP AMAN yang TIDAK boleh diblokir |
| **Blacklist** | Daftar IP BAHAYA yang harus diblokir (SAGEDRAL isi otomatis) |
| **Threshold** | Ambang batas skor untuk menentukan ALERT / BLOCK |
| **Inline Mode** | SAGEDRAL diletakkan DI TENGAH jalur trafik (Gateway) → IPS efektif |
| **SPAN Mode** | SAGEDRAL hanya terima salinan trafik → IPS kurang efektif |
| **Retrain** | Proses update model ML dengan data baru (Adaptive Learning) |

---

## 12. Cheat Sheet: Referensi Cepat

### 🚀 Quick Start 5 Menit (Ubuntu 22.04, Test Mode)
```bash
# 1. Install deps
sudo apt install -y python3-venv libpcap-dev nftables git

# 2. Clone & install
git clone <repo> && cd sagedral-ml
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# 3. Init model (WAJIB!)
sudo .venv/bin/python -m sagedral_ml.cli model init

# 4. Generate config template
mkdir -p ~/.config/sagedral
python -m sagedral_ml.cli config template > ~/.config/sagedral/config.toml

# 5. Start + Seed Demo (NO CAPTURE, untuk lihat UI)
sudo .venv/bin/python -m sagedral_ml.main --no-capture
# (Terminal 2)
python -m scripts.seed_demo

# 6. Buka browser → http://localhost:8000 ✅
```

### 🔧 Perintah Troubleshooting Penting
```bash
# Cek status service
sudo systemctl status sagedral-ml

# Lihat log live
sudo journalctl -u sagedral-ml -f

# Cek capture
sudo sagedral-ml selftest capture

# Cek IP blocklist aktif (nftables)
sudo nft list set inet sagedral blocklist

# Manual unblock (darurat)
sudo nft delete element inet sagedral blocklist { 1.2.3.4 }

# Cek API sehat
curl http://localhost:8000/api/v1/status | jq
```

### 🌐 Lokasi File Penting
| Tujuan | Lokasi Default |
|---|---|
| **Config system level** | `/etc/sagedral/config.toml` |
| **Config user level** | `~/.config/sagedral/config.toml` |
| **Database SQLite** | `/var/lib/sagedral-ml/sagedral.db` |
| **Folder Model ML (.pkl)** | `/var/lib/sagedral-ml/models/` |
| **Log file** | `/var/log/sagedral-ml.log` |
| **Source Code CLI** | [cli.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/cli.py) |
| **Source Code Main** | [main.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/main.py) |
| **Source Code IPS Response** | [response.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/ips/response.py) |

### ⚖️ Daftar Signature Rules Default
| Rule ID | Nama | Severity | Tipe Serangan |
|---|---|---|---|
| SIG-001 | SYN Flood | HIGH | DoS |
| SIG-002 | Port Scan (SYN) | MEDIUM | Reconnaissance |
| SIG-003 | ICMP Flood | HIGH | DoS |
| SIG-004 | Large Outbound Transfer | MEDIUM | Exfiltration |
| SIG-005 | Brute Force SSH | HIGH | BruteForce |
| SIG-006 | Brute Force RDP | HIGH | BruteForce |
| SIG-007 | UDP Flood | HIGH | DoS |

---

> **📚 Referensi Lebih Lanjut:**
> - Untuk detail arsitektur teknis → [prd.md](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/prd.md)
> - Untuk panduan install di WSL2 → [walkthrough.md](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/walkthrough.md)
> - Test scripts: Folder `scripts/testing/` untuk simulasi serangan tanpa bahaya nyata
