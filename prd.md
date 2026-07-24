# SAGEDRAL-ML — Product Requirements Document (PRD)

> **S**mart **A**daptive **G**uardian for **E**nhanced **D**etection, **R**esponse, and **A**daptive **L**earning — **ML**
>
> Version: `1.0.0-draft`  
> Last Updated: `2026-07-24`  
> Status: **LOCKED ARCHITECTURE**

---

## Table of Contents

1. [Overview & Vision](#1-overview--vision)
2. [Goals & Non-Goals](#2-goals--non-goals)
3. [Target Users](#3-target-users)
4. [System Architecture](#4-system-architecture)
5. [Module Specifications](#5-module-specifications)
   - 5.1 [Capture Module (Scapy)](#51-capture-module-scapy)
   - 5.2 [Feature Extraction Module](#52-feature-extraction-module)
   - 5.3 [Signature Detection Engine](#53-signature-detection-engine)
   - 5.4 [ML Detection Engine (LightGBM)](#54-ml-detection-engine-lightgbm)
   - 5.5 [Decision Engine](#55-decision-engine)
   - 5.6 [IPS Response Module](#56-ips-response-module)
   - 5.7 [Backend API (FastAPI)](#57-backend-api-fastapi)
   - 5.8 [Database Layer (SQLite)](#58-database-layer-sqlite)
   - 5.9 [React Dashboard](#59-react-dashboard)
6. [Data Flow & Lifecycle](#6-data-flow--lifecycle)
7. [API Contract](#7-api-contract)
8. [Database Schema](#8-database-schema)
9. [Configuration System](#9-configuration-system)
10. [Packaging & Installation](#10-packaging--installation)
11. [Non-Functional Requirements](#11-non-functional-requirements)
12. [Security Considerations](#12-security-considerations)
13. [Directory Structure](#13-directory-structure)
14. [Glossary](#14-glossary)

---

## 1. Overview & Vision

**SAGEDRAL-ML** adalah sebuah *installable CLI tool* untuk sistem Linux yang berfungsi sebagai **Network Intrusion Detection and Prevention System (NIDPS)** berbasis Machine Learning.

### Apa yang dilakukan SAGEDRAL-ML?

| Fungsi | Deskripsi |
|---|---|
| **Deteksi** | Mendeteksi ancaman jaringan secara real-time menggunakan kombinasi Signature Rules dan ML (LightGBM) |
| **Pencegahan** | Secara otomatis memblokir IP/traffic mencurigakan melalui nftables/iptables |
| **Monitoring** | Menyediakan dashboard web (React) untuk visualisasi traffic, alert, dan konfigurasi |
| **Adaptasi** | Model ML dapat di-retrain dengan data baru (Adaptive Learning) |

### Tagline

> *"Detect. Prevent. Adapt — Powered by Machine Learning."*

### Prinsip Desain Utama

- **Ringan**: Dioptimalkan untuk berjalan di mesin dengan spesifikasi rendah (min. Core i3, 4GB RAM).
- **Modular**: Setiap komponen bisa dikembangkan atau diganti secara independen.
- **Installable**: Output final adalah sebuah tool yang dapat diinstall dengan `pip install sagedral-ml` atau via script installer.
- **Observable**: Semua event dicatat, semua keputusan bisa di-audit.

---

## 2. Goals & Non-Goals

### Goals (In Scope)

- [x] Real-time packet capture via Scapy pada interface jaringan Linux
- [x] Ekstraksi fitur network flow dari raw packets
- [x] Deteksi ancaman berbasis Signature Rules (rule-based Python)
- [x] Deteksi ancaman berbasis ML (LightGBM) — anomaly + classification
- [x] Hybrid decision engine (kombinasi signature + ML score)
- [x] IPS action: block IP via nftables/iptables
- [x] IPS action: drop packet via Scapy
- [x] Logging semua event ke SQLite
- [x] REST API via FastAPI untuk komunikasi backend-frontend
- [x] WebSocket real-time untuk push alert ke dashboard
- [x] React dashboard: visualisasi traffic, alert list, manual block, konfigurasi
- [x] Packaging sebagai installable Python tool
- [x] Systemd service untuk auto-start

### Non-Goals (Out of Scope — v1.0)

- [ ] Deep Packet Inspection (DPI) konten layer 7
- [ ] Integrasi SIEM eksternal (Splunk, Elastic)
- [ ] Distributed / multi-node deployment
- [ ] GPU-accelerated inference
- [ ] Mobile app dashboard
- [ ] Cloud deployment / SaaS mode
- [ ] Support Windows/macOS
- [ ] Redis / message broker (menggunakan `queue.Queue`)

---

## 3. Target Users

### Primary User: Security Engineer / Sysadmin

- Memahami dasar-dasar jaringan (IP, TCP/UDP, port)
- Familiar dengan Linux command line
- Tidak harus memahami Machine Learning secara mendalam

### Secondary User: Junior Developer / AI Agent

- PRD ini dirancang agar detail dan eksplisit sehingga junior developer atau AI agent dapat mengimplementasikan setiap modul tanpa asumsi tambahan.
- Setiap modul memiliki input, output, dan kontrak yang terdefinisi jelas.

### Installation Environment

| Kriteria | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 20.04 LTS | Ubuntu 22.04 LTS |
| CPU | Core i3 (2 core) | Core i5+ (4 core) |
| RAM | 4 GB | 8 GB |
| Storage | 10 GB | 20 GB |
| Python | 3.10 | 3.11+ |
| Hak akses | `sudo` / `root` | root |
| Network | 1 NIC aktif | 1+ NIC |

---

## 4. System Architecture

### 4.1 High-Level Architecture Diagram

```
+---------------------------------------------------------------------+
|                         SAGEDRAL-ML SYSTEM                          |
|                                                                     |
|  [Network Interface]  (eth0 / wlan0 / etc.)                         |
|         |                                                           |
|         v  promiscuous mode                                         |
|  +-------------------+                                              |
|  |  CAPTURE MODULE   |  <- Scapy AsyncSniffer                       |
|  |                   |     Thread-safe packet queue                 |
|  +--------+----------+                                              |
|           | raw Packet objects                                      |
|           v                                                         |
|  +-------------------+                                              |
|  | FEATURE           |  <- Flow aggregation (5-tuple key)           |
|  | EXTRACTION        |     Timeout-based flow completion            |
|  +--------+----------+                                              |
|           | FlowRecord dict                                         |
|           v                                                         |
|  +-----------------------------+                                    |
|  |      HYBRID DETECTION       |                                    |
|  |  +----------------------+   |                                    |
|  |  | Signature Engine     |   |  <- Rule-based Python              |
|  |  +----------+-----------+   |                                    |
|  |             | sig_result    |                                    |
|  |  +----------------------+   |                                    |
|  |  | LightGBM ML Engine   |   |  <- Anomaly + Classification       |
|  |  +----------+-----------+   |                                    |
|  |             | ml_result     |                                    |
|  +-------------+---------------+                                    |
|                |                                                    |
|         v  combined DetectionResult                                 |
|  +-------------------+                                              |
|  | DECISION ENGINE   |  <- Score threshold check                    |
|  |                   |     Priority & deduplication                 |
|  +--------+----------+                                              |
|           | AlertEvent (if threat)                                  |
|           v                                                         |
|  +-------------------+     +-------------------------+             |
|  | IPS RESPONSE      |---->|  nftables/iptables      | Block IP    |
|  | MODULE            |     +-------------------------+             |
|  |                   |---->  Drop packet (Scapy)                   |
|  |                   |---->  Log to SQLite                         |
|  +--------+----------+                                              |
|           | AlertEvent                                              |
|           v                                                         |
|  +-------------------+                                              |
|  | FastAPI BACKEND   |  <- REST API + WebSocket                     |
|  |                   |     queue.Queue -> WebSocket broadcast        |
|  +--------+----------+                                              |
|           | HTTP / WebSocket                                        |
|           v                                                         |
|  +-------------------+                                              |
|  | REACT DASHBOARD   |  <- Vite + Tailwind + Recharts               |
|  |                   |     Monitoring, Alert, Block, Config         |
|  +-------------------+                                              |
+---------------------------------------------------------------------+
```

### 4.2 Thread / Process Model

```
Main Process
|
+-- Thread 1: CaptureThread (Scapy AsyncSniffer)
|     +-- pushes raw packets -> packet_queue (queue.Queue, maxsize=10000)
|
+-- Thread 2: ProcessingThread
|     +-- reads from packet_queue
|     +-- calls FeatureExtractor
|     +-- calls HybridDetector (Signature + ML)
|     +-- calls DecisionEngine
|     +-- calls IPSModule -> pushes AlertEvent -> alert_queue
|
+-- Thread 3: FastAPI (uvicorn, async event loop)
      +-- reads from alert_queue -> broadcasts via WebSocket
      +-- serves REST API endpoints
      +-- writes to SQLite via async SQLAlchemy
```

### 4.3 Technology Stack (LOCKED)

| Layer | Tool | Versi Target | Alasan |
|---|---|---|---|
| Capture | Scapy | >= 2.5.0 | Promiscuous mode, ringan, Pythonic |
| Feature Extraction | Custom Python + dpkt | dpkt >= 1.9.8 | Kontrol penuh, low RAM |
| ML Model | LightGBM | >= 4.0.0 | Cepat, hemat resource, no GPU |
| Signature | Pure Python rule-based | — | Hybrid dengan ML |
| Backend | FastAPI | >= 0.111.0 | Async, WebSocket, OpenAPI docs |
| ASGI Server | Uvicorn | >= 0.29.0 | Lightweight production server |
| Queue | queue.Queue (stdlib) | — | Tidak perlu Redis |
| IPS | nftables + iptables fallback | — | Native Linux, cepat |
| Database | SQLite via SQLAlchemy async | SQLAlchemy >= 2.0 | Ringan, tanpa server |
| Dashboard | React 18 + Vite 5 + Tailwind 3 + Recharts | — | Modern SPA |
| WebSocket client | native browser WebSocket API | — | Tanpa library tambahan |

---

## 5. Module Specifications

---

### 5.1 Capture Module (Scapy)

**File**: `sagedral_ml/capture/sniffer.py`

#### 5.1.1 Tujuan

Menangkap semua packet yang masuk/keluar pada network interface yang dikonfigurasi dan memasukkannya ke dalam shared `queue.Queue`.

#### 5.1.2 Input

| Parameter | Tipe | Sumber | Keterangan |
|---|---|---|---|
| `interface` | `str` | Config / CLI | Nama interface: `eth0`, `wlan0`, dll |
| `bpf_filter` | `str` | Config | BPF filter string, default: `""` |
| `packet_queue` | `queue.Queue` | Injected | Queue shared dengan ProcessingThread |
| `promiscuous` | `bool` | Config | Default: `True` |

#### 5.1.3 Output

Memasukkan objek `scapy.packet.Packet` ke dalam `packet_queue`.

#### 5.1.4 Implementasi Detail

```python
# sagedral_ml/capture/sniffer.py

from scapy.all import AsyncSniffer, conf
import queue
import threading
import logging

logger = logging.getLogger(__name__)

class PacketCapture:
    """
    Komponen untuk menangkap packet jaringan secara real-time.
    Menggunakan Scapy AsyncSniffer agar non-blocking.
    
    PENTING: Harus dijalankan sebagai root (diperlukan untuk promiscuous mode).
    """

    def __init__(
        self,
        interface: str,
        packet_queue: queue.Queue,
        bpf_filter: str = "",
        promiscuous: bool = True,
    ):
        self.interface = interface
        self.packet_queue = packet_queue
        self.bpf_filter = bpf_filter
        self.promiscuous = promiscuous
        self._sniffer: AsyncSniffer | None = None
        self._running = threading.Event()

    def _packet_handler(self, packet) -> None:
        """Callback dipanggil Scapy untuk setiap packet yang ditangkap."""
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            # Jika queue penuh, drop packet — JANGAN raise exception
            logger.warning("packet_queue penuh, packet di-drop")

    def start(self) -> None:
        """Mulai sniffing secara async."""
        conf.promisc = self.promiscuous
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self._packet_handler,
            store=False,   # KRITIS: jangan simpan packet di memory Scapy
        )
        self._sniffer.start()
        self._running.set()
        logger.info(f"PacketCapture dimulai pada interface {self.interface}")

    def stop(self) -> None:
        """Hentikan sniffing secara graceful."""
        if self._sniffer:
            self._sniffer.stop()
        self._running.clear()
        logger.info("PacketCapture dihentikan")

    @property
    def is_running(self) -> bool:
        return self._running.is_set()
```

#### 5.1.5 Error Handling

| Kondisi Error | Penanganan |
|---|---|
| Interface tidak ditemukan | Raise `ValueError` dengan pesan deskriptif |
| Tidak ada izin root | Raise `PermissionError` dengan instruksi cara pakai `sudo` |
| `packet_queue` penuh | Log WARNING, skip packet (tidak raise exception) |
| Scapy crash | Log CRITICAL, restart sniffer otomatis (max 3x dalam 5 menit) |

#### 5.1.6 Konfigurasi Terkait

```toml
[capture]
interface = "eth0"          # WAJIB diisi user sebelum menjalankan
bpf_filter = ""             # Contoh: "tcp port 80 or udp"
promiscuous = true
queue_maxsize = 10000       # Ukuran max packet_queue
```

---

### 5.2 Feature Extraction Module

**File**: `sagedral_ml/features/extractor.py`

#### 5.2.1 Tujuan

Mengagregasi raw packets menjadi **network flow records** berdasarkan 5-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)` dan mengekstrak 28 fitur statistik dari setiap flow.

#### 5.2.2 Konsep Flow

Sebuah *flow* adalah sekumpulan packet dengan 5-tuple yang sama. Flow dianggap **selesai** jika:
- **TCP FIN/RST**: ditemukan packet dengan flag FIN atau RST
- **Timeout**: tidak ada packet baru selama `flow_timeout` detik (default: 60)
- **Max packets**: jumlah packet melebihi `max_packets_per_flow` (default: 1000)

#### 5.2.3 Daftar 28 Fitur yang Diekstrak

| # | Nama Fitur | Tipe | Keterangan |
|---|---|---|---|
| 1 | `duration` | float | Durasi flow dalam detik |
| 2 | `total_fwd_packets` | int | Jumlah packet forward (src->dst) |
| 3 | `total_bwd_packets` | int | Jumlah packet backward (dst->src) |
| 4 | `total_fwd_bytes` | int | Total byte forward |
| 5 | `total_bwd_bytes` | int | Total byte backward |
| 6 | `fwd_packet_len_mean` | float | Rata-rata panjang packet forward |
| 7 | `fwd_packet_len_std` | float | Std deviasi panjang packet forward |
| 8 | `bwd_packet_len_mean` | float | Rata-rata panjang packet backward |
| 9 | `bwd_packet_len_std` | float | Std deviasi panjang packet backward |
| 10 | `flow_bytes_per_sec` | float | Throughput byte per detik |
| 11 | `flow_packets_per_sec` | float | Throughput packet per detik |
| 12 | `fwd_iat_mean` | float | Rata-rata inter-arrival time forward |
| 13 | `fwd_iat_std` | float | Std inter-arrival time forward |
| 14 | `bwd_iat_mean` | float | Rata-rata inter-arrival time backward |
| 15 | `bwd_iat_std` | float | Std inter-arrival time backward |
| 16 | `psh_flag_count` | int | Jumlah packet dengan flag PSH |
| 17 | `urg_flag_count` | int | Jumlah packet dengan flag URG |
| 18 | `syn_flag_count` | int | Jumlah packet dengan flag SYN |
| 19 | `fin_flag_count` | int | Jumlah packet dengan flag FIN |
| 20 | `rst_flag_count` | int | Jumlah packet dengan flag RST |
| 21 | `ack_flag_count` | int | Jumlah packet dengan flag ACK |
| 22 | `avg_fwd_segment_size` | float | Rata-rata ukuran segment forward |
| 23 | `avg_bwd_segment_size` | float | Rata-rata ukuran segment backward |
| 24 | `fwd_header_len` | int | Total panjang header forward |
| 25 | `bwd_header_len` | int | Total panjang header backward |
| 26 | `down_up_ratio` | float | Rasio total_bwd_bytes / total_fwd_bytes |
| 27 | `protocol` | int | Nomor protokol (6=TCP, 17=UDP, 1=ICMP) |
| 28 | `dst_port` | int | Port tujuan |

#### 5.2.4 Data Class: FlowRecord

```python
# sagedral_ml/features/models.py

from dataclasses import dataclass, field
import time

@dataclass
class FlowRecord:
    """Representasi satu network flow yang sedang atau sudah selesai dikumpulkan."""

    # 5-tuple identifier (kunci unik untuk setiap flow)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP

    # Metadata waktu
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0

    # Statistik forward (src->dst)
    total_fwd_packets: int = 0
    total_fwd_bytes: int = 0
    fwd_packet_lengths: list = field(default_factory=list)
    fwd_iat_list: list = field(default_factory=list)  # inter-arrival times

    # Statistik backward (dst->src)
    total_bwd_packets: int = 0
    total_bwd_bytes: int = 0
    bwd_packet_lengths: list = field(default_factory=list)
    bwd_iat_list: list = field(default_factory=list)

    # TCP Flag counters
    syn_flag_count: int = 0
    fin_flag_count: int = 0
    rst_flag_count: int = 0
    psh_flag_count: int = 0
    ack_flag_count: int = 0
    urg_flag_count: int = 0

    # Header lengths
    fwd_header_len: int = 0
    bwd_header_len: int = 0

    def to_feature_vector(self) -> dict:
        """
        Konversi FlowRecord menjadi dict 28 fitur numerik
        yang siap dimasukkan ke ML model.
        
        Return: dict dengan 28 key sesuai daftar fitur di PRD section 5.2.3
        """
        import numpy as np
        duration = max(self.end_time - self.start_time, 1e-6)
        fwd_lens = self.fwd_packet_lengths or [0]
        bwd_lens = self.bwd_packet_lengths or [0]
        fwd_iats = self.fwd_iat_list or [0]
        bwd_iats = self.bwd_iat_list or [0]
        total_bytes = self.total_fwd_bytes + self.total_bwd_bytes
        total_pkts = self.total_fwd_packets + self.total_bwd_packets

        return {
            "duration": duration,
            "total_fwd_packets": self.total_fwd_packets,
            "total_bwd_packets": self.total_bwd_packets,
            "total_fwd_bytes": self.total_fwd_bytes,
            "total_bwd_bytes": self.total_bwd_bytes,
            "fwd_packet_len_mean": float(np.mean(fwd_lens)),
            "fwd_packet_len_std": float(np.std(fwd_lens)),
            "bwd_packet_len_mean": float(np.mean(bwd_lens)),
            "bwd_packet_len_std": float(np.std(bwd_lens)),
            "flow_bytes_per_sec": total_bytes / duration,
            "flow_packets_per_sec": total_pkts / duration,
            "fwd_iat_mean": float(np.mean(fwd_iats)),
            "fwd_iat_std": float(np.std(fwd_iats)),
            "bwd_iat_mean": float(np.mean(bwd_iats)),
            "bwd_iat_std": float(np.std(bwd_iats)),
            "psh_flag_count": self.psh_flag_count,
            "urg_flag_count": self.urg_flag_count,
            "syn_flag_count": self.syn_flag_count,
            "fin_flag_count": self.fin_flag_count,
            "rst_flag_count": self.rst_flag_count,
            "ack_flag_count": self.ack_flag_count,
            "avg_fwd_segment_size": float(np.mean(fwd_lens)),
            "avg_bwd_segment_size": float(np.mean(bwd_lens)),
            "fwd_header_len": self.fwd_header_len,
            "bwd_header_len": self.bwd_header_len,
            "down_up_ratio": self.total_bwd_bytes / max(self.total_fwd_bytes, 1),
            "protocol": self.protocol,
            "dst_port": self.dst_port,
        }
```

#### 5.2.5 FlowAggregator (Spesifikasi Implementasi)

```python
# sagedral_ml/features/extractor.py

class FlowAggregator:
    """
    Mengagregasi packet ke dalam flows berdasarkan 5-tuple.
    
    Alur kerja:
    1. Terima packet dari packet_queue
    2. Parse header: src_ip, dst_ip, src_port, dst_port, protocol
    3. Buat key = tuple(src_ip, dst_ip, src_port, dst_port, proto)
    4. Jika flow belum ada di active_flows -> buat FlowRecord baru
    5. Update statistik flow (bytes, flags, IAT, dll)
    6. Cek completion: TCP FIN/RST, timeout, atau max_packets
    7. Jika selesai -> put ke flow_queue untuk diproses detection
    8. Jalankan cleanup timeout setiap 30 detik via Timer thread
    """

    def __init__(self, flow_queue: queue.Queue, config: dict):
        self.active_flows: dict[tuple, FlowRecord] = {}
        self.flow_queue = flow_queue
        self.flow_timeout: int = config.get("flow_timeout", 60)
        self.max_packets_per_flow: int = config.get("max_packets_per_flow", 1000)
        self._lock = threading.Lock()

    def process_packet(self, packet) -> None:
        """
        Proses satu packet: parse, update FlowRecord, dan cek completion.
        Dipanggil oleh ProcessingThread untuk setiap packet.
        """
        # TODO: implementasi di sini
        ...

    def _complete_flow(self, key: tuple) -> None:
        """
        Finalisasi FlowRecord: set end_time, put ke flow_queue, hapus dari active_flows.
        Harus dipanggil dengan self._lock sudah dipegang.
        """
        ...

    def cleanup_timeouts(self) -> None:
        """
        Cek semua active_flows, complete yang sudah timeout.
        Dipanggil secara periodik oleh Timer thread.
        """
        ...
```

#### 5.2.6 Konfigurasi Terkait

```toml
[feature_extraction]
flow_timeout = 60              # Detik sebelum flow dianggap selesai karena timeout
max_packets_per_flow = 1000   # Batas maksimum packet per flow sebelum di-complete
```

---

### 5.3 Signature Detection Engine

**File**: `sagedral_ml/detection/signature_engine.py`

#### 5.3.1 Tujuan

Mendeteksi pola serangan yang dikenal berdasarkan aturan eksplisit (rule-based). Ini adalah lapisan **pertama** dari hybrid detection.

#### 5.3.2 Format Rule (Python Dict)

```python
# sagedral_ml/detection/rules/default_rules.py

SIGNATURE_RULES: list[dict] = [
    {
        "rule_id": "SIG-001",
        "name": "SYN Flood",
        "description": "Deteksi SYN flood: banyak SYN tanpa ACK dalam waktu singkat",
        "severity": "HIGH",
        "condition": lambda flow: (
            flow["syn_flag_count"] > 100 and
            flow["ack_flag_count"] < 10 and
            flow["duration"] < 5.0
        ),
        "attack_type": "DoS",
    },
    {
        "rule_id": "SIG-002",
        "name": "Port Scan (SYN)",
        "description": "Banyak koneksi SYN ke berbagai port tanpa FIN",
        "severity": "MEDIUM",
        "condition": lambda flow: (
            flow["total_fwd_packets"] < 3 and
            flow["syn_flag_count"] >= 1 and
            flow["fin_flag_count"] == 0
        ),
        "attack_type": "Reconnaissance",
    },
    {
        "rule_id": "SIG-003",
        "name": "ICMP Flood",
        "description": "Volume ICMP packet sangat tinggi",
        "severity": "HIGH",
        "condition": lambda flow: (
            flow["protocol"] == 1 and
            flow["flow_packets_per_sec"] > 1000
        ),
        "attack_type": "DoS",
    },
    {
        "rule_id": "SIG-004",
        "name": "Large Outbound Transfer",
        "description": "Transfer data keluar > 100MB — potensi exfiltration",
        "severity": "MEDIUM",
        "condition": lambda flow: (
            flow["total_bwd_bytes"] > 100_000_000
        ),
        "attack_type": "Exfiltration",
    },
    {
        "rule_id": "SIG-005",
        "name": "Brute Force SSH",
        "description": "Banyak koneksi TCP ke port 22 dalam waktu singkat",
        "severity": "HIGH",
        "condition": lambda flow: (
            flow["dst_port"] == 22 and
            flow["total_fwd_packets"] > 50 and
            flow["duration"] < 30
        ),
        "attack_type": "BruteForce",
    },
    {
        "rule_id": "SIG-006",
        "name": "Brute Force RDP",
        "description": "Banyak koneksi TCP ke port 3389 (RDP)",
        "severity": "HIGH",
        "condition": lambda flow: (
            flow["dst_port"] == 3389 and
            flow["total_fwd_packets"] > 30 and
            flow["duration"] < 60
        ),
        "attack_type": "BruteForce",
    },
    {
        "rule_id": "SIG-007",
        "name": "UDP Flood",
        "description": "Volume UDP packet sangat tinggi",
        "severity": "HIGH",
        "condition": lambda flow: (
            flow["protocol"] == 17 and
            flow["flow_packets_per_sec"] > 5000
        ),
        "attack_type": "DoS",
    },
]
```

#### 5.3.3 Output: SignatureResult

```python
from dataclasses import dataclass

@dataclass
class SignatureResult:
    matched: bool              # True jika ada rule yang cocok
    matched_rules: list[str]   # List rule_id yang match, contoh: ["SIG-001", "SIG-003"]
    max_severity: str          # Severity tertinggi: "LOW", "MEDIUM", "HIGH", "CRITICAL"
    attack_types: list[str]    # Jenis serangan yang terdeteksi
    signature_score: float     # 0.0 - 1.0, sesuai max_severity
```

#### 5.3.4 Severity Score Mapping

| Severity | Score |
|---|---|
| (tidak ada match) | 0.0 |
| LOW | 0.25 |
| MEDIUM | 0.5 |
| HIGH | 0.75 |
| CRITICAL | 1.0 |

#### 5.3.5 Alur Proses SignatureEngine.evaluate()

1. Terima `feature_vector: dict` dari `FlowRecord.to_feature_vector()`
2. Iterasi semua rules dalam `SIGNATURE_RULES`
3. Skip rules yang ada di `config.signature.disabled_rules`
4. Evaluasi `condition(feature_vector)` dengan try/except (aman dari error lambda)
5. Kumpulkan semua matched rules
6. Hitung `max_severity` dan `signature_score`
7. Return `SignatureResult`

#### 5.3.6 Konfigurasi

```toml
[signature]
enabled = true
custom_rules_file = ""          # Path ke custom rules Python file (opsional)
disabled_rules = []             # Contoh: ["SIG-002"] untuk nonaktifkan Port Scan rule
```

---

### 5.4 ML Detection Engine (LightGBM)

**File**: `sagedral_ml/detection/ml_engine.py`

#### 5.4.1 Tujuan

Mendeteksi ancaman menggunakan model ML terlatih. Mampu mendeteksi **anomali** (behavior tidak normal) dan mengklasifikasikan **tipe serangan**.

#### 5.4.2 Model Architecture: Two-Stage Detection

**Stage 1 — Anomaly Detector (Binary Classification)**
- Model: `LGBMClassifier` dengan `objective='binary'`
- Input: vector 28 fitur (numpy array, shape [1, 28])
- Output: `anomaly_score` = probability class 1 (anomaly), range 0.0 – 1.0

**Stage 2 — Attack Classifier (Multi-class)**
- Hanya dijalankan JIKA `anomaly_score > anomaly_threshold`
- Model: `LGBMClassifier` dengan `objective='multiclass'`
- Input: vector 28 fitur (sama)
- Output: `attack_class` (string label), `class_confidence` (probability tertinggi)

#### 5.4.3 Label Serangan

| Label | Keterangan |
|---|---|
| `NORMAL` | Traffic normal |
| `DDoS` | Distributed Denial of Service |
| `PortScan` | Port scanning / reconnaissance |
| `BruteForce` | Brute force login (SSH, RDP, HTTP) |
| `DoS_Slowloris` | DoS Slowloris |
| `WebAttack` | SQL Injection, XSS, Command Injection |
| `Botnet` | Traffic dari botnet |
| `Infiltration` | Infiltration attack |
| `Exfiltration` | Data exfiltration |

#### 5.4.4 Training Data

| Dataset | URL | Keterangan |
|---|---|---|
| CICIDS 2017 | https://www.unb.ca/cic/datasets/ids-2017.html | Dataset utama |
| CICIDS 2018 | https://www.unb.ca/cic/datasets/ids-2018.html | Supplement dataset |

**Preprocessing Steps (untuk training script):**
1. Load CSV dataset dengan pandas
2. Drop kolom yang tidak termasuk dalam 28 fitur yang didefinisikan
3. Encode label serangan menjadi integer dengan `LabelEncoder`
4. Handle nilai NaN: replace dengan median kolom
5. Handle nilai Inf: replace dengan nilai maksimum yang valid
6. Feature scaling: **tidak diperlukan** (LightGBM tidak sensitif terhadap skala)
7. Train/validation split: 80/20 stratified berdasarkan label
8. Train model dengan early stopping pada validation set
9. Simpan model dengan `joblib.dump()` ke `.pkl` file

#### 5.4.5 Model Storage Paths

```
/var/lib/sagedral-ml/models/
  anomaly_detector.pkl       <- Model binary (NORMAL vs ANOMALY)
  attack_classifier.pkl      <- Model multiclass (tipe serangan)
  feature_names.json         <- List 28 nama fitur dalam urutan yang benar
```

#### 5.4.6 Output: MLResult

```python
@dataclass
class MLResult:
    anomaly_score: float          # 0.0-1.0: probability bahwa flow adalah anomaly
    is_anomaly: bool              # True jika anomaly_score > anomaly_threshold
    attack_class: str             # "NORMAL", "DDoS", "PortScan", dll
    class_confidence: float       # Confidence classifier (0.0-1.0)
    model_version: str            # Versi model, dibaca dari metadata file
```

#### 5.4.7 Konfigurasi

```toml
[ml]
enabled = true
anomaly_threshold = 0.7           # Threshold untuk anomaly (0.0-1.0)
classifier_threshold = 0.6        # Min confidence untuk classifier
model_dir = "/var/lib/sagedral-ml/models"
retrain_on_startup = false        # Jangan retrain otomatis saat startup
```

#### 5.4.8 Fallback jika Model Tidak Ada

```
Jika model file tidak ditemukan atau gagal load:
  -> Log WARNING: "Model tidak ditemukan, ML detection dinonaktifkan"
  -> Return MLResult(anomaly_score=0.0, is_anomaly=False, attack_class="UNKNOWN")
  -> Sistem tetap berjalan dengan HANYA Signature Engine aktif
  -> JANGAN crash atau raise exception ke caller
```

---

### 5.5 Decision Engine

**File**: `sagedral_ml/detection/decision_engine.py`

#### 5.5.1 Tujuan

Menggabungkan hasil Signature Engine dan ML Engine menjadi satu keputusan final: apakah ini ancaman dan apa tindakannya.

#### 5.5.2 Scoring Formula

```
final_score = (weight_sig * signature_score) + (weight_ml * anomaly_score)

Default weights (dikonfigurasi di config.toml):
  weight_sig = 0.4
  weight_ml  = 0.6

Contoh:
  signature_score = 0.75 (HIGH)
  anomaly_score   = 0.85
  final_score     = (0.4 * 0.75) + (0.6 * 0.85) = 0.30 + 0.51 = 0.81
```

#### 5.5.3 Decision Logic

```python
def decide(sig_result: SignatureResult, ml_result: MLResult, src_ip: str) -> DecisionResult:
    
    # Hitung final_score
    final_score = (weight_sig * sig_result.signature_score) + (weight_ml * ml_result.anomaly_score)
    
    # OVERRIDE: Signature HIGH/CRITICAL = langsung block, bypass threshold
    if sig_result.max_severity in ("HIGH", "CRITICAL"):
        is_threat = True
        action = "BLOCK"
    
    # Cek threshold
    elif final_score >= config.block_threshold:     # default: 0.7
        is_threat = True
        action = "BLOCK"
    
    elif final_score >= config.alert_threshold:     # default: 0.5
        is_threat = True
        action = "ALERT"   # Log dan notifikasi, tapi tidak block
    
    else:
        is_threat = False
        action = "ALLOW"
    
    # DEDUPLICATION: Skip jika IP sudah diblokir
    if is_ip_blocked(src_ip):
        action = "ALREADY_BLOCKED"
        is_threat = False
    
    # Tentukan severity final dari score
    severity = score_to_severity(final_score)
    
    return DecisionResult(
        is_threat=is_threat,
        final_score=final_score,
        action=action,
        attack_type=ml_result.attack_class or sig_result.attack_types[0] if sig_result.attack_types else "Unknown",
        severity=severity,
        confidence=ml_result.class_confidence,
    )
```

#### 5.5.4 Severity dari Score

| Score Range | Severity |
|---|---|
| 0.0 – 0.25 | LOW |
| 0.25 – 0.5 | MEDIUM |
| 0.5 – 0.75 | HIGH |
| 0.75 – 1.0 | CRITICAL |

#### 5.5.5 Output: DecisionResult

```python
@dataclass
class DecisionResult:
    is_threat: bool
    final_score: float           # 0.0-1.0
    action: str                  # "ALLOW", "ALERT", "BLOCK", "ALREADY_BLOCKED"
    attack_type: str             # "DDoS", "PortScan", dll
    severity: str                # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: float            # 0.0-1.0
```

#### 5.5.6 Konfigurasi

```toml
[decision]
alert_threshold = 0.5         # Score >= ini -> buat alert (tidak block)
block_threshold = 0.7         # Score >= ini -> block IP
weight_signature = 0.4        # Bobot signature dalam scoring
weight_ml = 0.6               # Bobot ML dalam scoring
dedup_window = 300            # Detik untuk deduplikasi alert per IP yang sama
```

---

### 5.6 IPS Response Module

**File**: `sagedral_ml/ips/response.py`

#### 5.6.1 Tujuan

Mengeksekusi tindakan pencegahan (block IP, log, notify) berdasarkan `DecisionResult`.

#### 5.6.2 Tindakan yang Didukung

| Action | Tool | Efek |
|---|---|---|
| `BLOCK_IP` | nftables / iptables | Semua packet dari/ke IP diblokir di level kernel |
| `UNBLOCK_IP` | nftables / iptables | Hapus rule block, IP dapat akses kembali |
| `LOG_ONLY` | SQLite + log file | Tidak ada aksi jaringan, hanya catat |
| `ALERT_ONLY` | WebSocket + SQLite | Push notifikasi ke dashboard |

#### 5.6.3 nftables Implementation (PREFERRED)

Deteksi ketersediaan: cek apakah binary `nft` ada di PATH dengan `shutil.which("nft")`.

Setup table saat startup (jalankan SEKALI sebagai root):
```bash
nft add table inet sagedral
nft add set inet sagedral blocklist { type ipv4_addr; }
nft add chain inet sagedral input { type filter hook input priority 0; }
nft add rule inet sagedral input ip saddr @blocklist drop
nft add chain inet sagedral output { type filter hook output priority 0; }
nft add rule inet sagedral output ip daddr @blocklist drop
```

Block IP:
```python
def block_ip_nftables(ip: str) -> bool:
    validated = validate_ip(ip)  # WAJIB validasi sebelum subprocess
    cmd = ["nft", "add", "element", "inet", "sagedral", "blocklist", f"{{ {validated} }}"]
    result = subprocess.run(cmd, capture_output=True, timeout=5)
    return result.returncode == 0
```

Unblock IP:
```python
def unblock_ip_nftables(ip: str) -> bool:
    validated = validate_ip(ip)
    cmd = ["nft", "delete", "element", "inet", "sagedral", "blocklist", f"{{ {validated} }}"]
    result = subprocess.run(cmd, capture_output=True, timeout=5)
    return result.returncode == 0
```

#### 5.6.4 iptables Fallback

```python
def block_ip_iptables(ip: str) -> bool:
    validated = validate_ip(ip)
    subprocess.run(["iptables", "-I", "INPUT", "-s", validated, "-j", "DROP"], timeout=5)
    subprocess.run(["iptables", "-I", "OUTPUT", "-d", validated, "-j", "DROP"], timeout=5)
    return True

def unblock_ip_iptables(ip: str) -> bool:
    validated = validate_ip(ip)
    subprocess.run(["iptables", "-D", "INPUT", "-s", validated, "-j", "DROP"], timeout=5)
    subprocess.run(["iptables", "-D", "OUTPUT", "-d", validated, "-j", "DROP"], timeout=5)
    return True
```

#### 5.6.5 Output: AlertEvent

```python
@dataclass
class AlertEvent:
    alert_id: str              # UUID v4 (gunakan uuid.uuid4())
    timestamp: float           # Unix timestamp (time.time())
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str              # "TCP", "UDP", "ICMP"
    attack_type: str           # "DDoS", "PortScan", "BruteForce", dll
    severity: str              # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    final_score: float         # 0.0-1.0
    action_taken: str          # "BLOCKED", "ALERTED", "ALLOWED"
    signature_matched: list[str]  # Rule ID yang cocok: ["SIG-001"]
    ml_anomaly_score: float    # 0.0-1.0
    flow_duration: float       # Durasi flow dalam detik
    total_bytes: int           # Total bytes dalam flow
```

#### 5.6.6 WHITELIST PROTECTION (KRITIS)

**Sebelum setiap block action**, SELALU lakukan pengecekan berikut:

```python
NEVER_BLOCK = {"127.0.0.1", "::1"}  # Hardcoded, tidak bisa di-override

def is_whitelisted(ip: str) -> bool:
    if ip in NEVER_BLOCK:
        return True
    if ip in config.ips.whitelist:
        return True
    if ip == get_default_gateway():  # Deteksi gateway saat startup
        return True
    return False
```

Jika IP di-whitelist: log WARNING, SKIP block, tetap buat AlertEvent dengan `action_taken="WHITELISTED"`.

#### 5.6.7 Konfigurasi

```toml
[ips]
enabled = true
preferred_backend = "nftables"   # "nftables" atau "iptables"
auto_unblock_after = 3600        # Detik (0 = permanent block)
whitelist = [
    "127.0.0.1",
    "::1",
]
```

---

### 5.7 Backend API (FastAPI)

**File**: `sagedral_ml/api/main.py`

**Base URL**: `http://localhost:8000`  
**Swagger Docs**: `http://localhost:8000/docs` (auto-generated)

#### 5.7.1 REST Endpoints — Detail

---

**GET `/api/v1/status`** — Status sistem

Response 200:
```json
{
  "status": "running",
  "uptime_seconds": 3600,
  "interface": "eth0",
  "packets_captured": 145000,
  "flows_processed": 2300,
  "alerts_total": 15,
  "blocked_ips_count": 3,
  "ml_model_loaded": true,
  "model_version": "1.0.0",
  "cpu_percent": 12.5,
  "ram_mb": 245
}
```

---

**GET `/api/v1/alerts`** — Daftar alert dengan filter dan pagination

Query Parameters:

| Param | Tipe | Default | Keterangan |
|---|---|---|---|
| `page` | int | 1 | Halaman |
| `limit` | int | 50 | Jumlah per halaman (max 200) |
| `severity` | str | null | "LOW", "MEDIUM", "HIGH", "CRITICAL" |
| `attack_type` | str | null | Filter tipe serangan |
| `src_ip` | str | null | Filter IP sumber |
| `start_time` | float | null | Unix timestamp awal |
| `end_time` | float | null | Unix timestamp akhir |

Response 200:
```json
{
  "total": 150,
  "page": 1,
  "limit": 50,
  "data": [
    {
      "alert_id": "550e8400-e29b-41d4-a716-446655440000",
      "timestamp": 1700000000.123,
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.1",
      "src_port": 54321,
      "dst_port": 22,
      "protocol": "TCP",
      "attack_type": "BruteForce",
      "severity": "HIGH",
      "final_score": 0.87,
      "action_taken": "BLOCKED",
      "signature_matched": ["SIG-005"],
      "ml_anomaly_score": 0.92,
      "flow_duration": 25.4,
      "total_bytes": 15200
    }
  ]
}
```

---

**GET `/api/v1/blocked-ips`** — Daftar IP yang sedang diblokir

Response 200:
```json
{
  "total": 3,
  "data": [
    {
      "ip": "192.168.1.100",
      "blocked_at": 1700000000.0,
      "reason": "BruteForce",
      "alert_id": "550e8400-...",
      "auto_unblock_at": 1700003600.0,
      "blocked_by": "system"
    }
  ]
}
```

---

**POST `/api/v1/blocked-ips`** — Manual block IP

Request Body:
```json
{
  "ip": "10.0.0.55",
  "reason": "Manual block by admin",
  "duration_seconds": 3600
}
```

Response 200:
```json
{ "success": true, "message": "IP 10.0.0.55 berhasil diblokir" }
```

Response 403 (jika IP di whitelist):
```json
{ "error": "WHITELISTED", "message": "IP 127.0.0.1 ada di whitelist dan tidak bisa diblokir" }
```

---

**DELETE `/api/v1/blocked-ips/{ip}`** — Manual unblock IP

Response 200:
```json
{ "success": true, "message": "IP 10.0.0.55 berhasil di-unblock" }
```

---

**GET `/api/v1/traffic/stats`** — Statistik traffic untuk chart

Query: `interval` ("1m","5m","1h","24h"), `limit` (max data points)

Response 200:
```json
{
  "interval": "1m",
  "data": [
    { "timestamp": 1700000000, "packets_per_sec": 1234, "bytes_per_sec": 56789, "alerts_count": 2, "flows_count": 45 }
  ]
}
```

---

**GET `/api/v1/config`** — Baca konfigurasi saat ini (JSON format)

**PUT `/api/v1/config`** — Update konfigurasi

Response 200:
```json
{
  "success": true,
  "message": "Konfigurasi diupdate.",
  "requires_restart": ["capture.interface"]
}
```

---

**POST `/api/v1/rules`** — Tambah custom signature rule

Request:
```json
{
  "rule_id": "SIG-CUSTOM-001",
  "name": "Custom Rule",
  "description": "Deskripsi",
  "severity": "HIGH",
  "condition_expr": "flow['dst_port'] == 3389 and flow['total_fwd_packets'] > 100",
  "attack_type": "RDP_BruteForce"
}
```

---

**GET `/api/v1/model/info`** — Info model ML

Response 200:
```json
{
  "anomaly_model": {
    "version": "1.0.0",
    "trained_at": "2024-01-01",
    "n_features": 28,
    "accuracy": 0.96,
    "f1_score": 0.94
  },
  "classifier_model": {
    "version": "1.0.0",
    "classes": ["NORMAL", "DDoS", "PortScan", "BruteForce"],
    "accuracy": 0.93
  }
}
```

#### 5.7.2 WebSocket Endpoint

**URL**: `ws://localhost:8000/ws/alerts`

Server -> Client Events:
```json
// Saat ada threat baru
{ "event": "new_alert", "data": { "alert_id": "...", "src_ip": "...", "attack_type": "DDoS", "severity": "HIGH" } }

// Setiap 5 detik — update statistik traffic
{ "event": "traffic_stats", "data": { "timestamp": 1700000000, "packets_per_sec": 1234, "bytes_per_sec": 56789, "active_flows": 45, "blocked_ips": 3 } }

// Setiap 30 detik — status sistem
{ "event": "system_status", "data": { "status": "running", "cpu_percent": 12.5, "ram_mb": 245 } }
```

Client -> Server:
```json
// Keep-alive ping
{ "event": "ping" }
```

**Auto-reconnect**: Client harus implement auto-reconnect dengan delay 3 detik jika koneksi terputus.

---

### 5.8 Database Layer (SQLite)

**File**: `sagedral_ml/database/models.py`, `sagedral_ml/database/crud.py`  
**Path**: `/var/lib/sagedral-ml/sagedral.db`

#### 5.8.1 Schema Lengkap

```sql
-- TABEL 1: alerts — semua ancaman yang terdeteksi
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT UNIQUE NOT NULL,        -- UUID v4
    timestamp REAL NOT NULL,              -- Unix timestamp float
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,                        -- "TCP", "UDP", "ICMP"
    attack_type TEXT,
    severity TEXT,                        -- "LOW", "MEDIUM", "HIGH", "CRITICAL"
    final_score REAL,
    action_taken TEXT,                    -- "BLOCKED", "ALERTED", "ALLOWED"
    signature_matched TEXT,               -- JSON array: '["SIG-001", "SIG-005"]'
    ml_anomaly_score REAL,
    flow_duration REAL,
    total_bytes INTEGER,
    created_at REAL DEFAULT (unixepoch('now','subsec'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type);

-- TABEL 2: blocked_ips — IP yang sedang atau pernah diblokir
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    blocked_at REAL NOT NULL,
    reason TEXT,
    alert_id TEXT,                        -- Referensi ke alerts.alert_id (soft)
    auto_unblock_at REAL,                 -- NULL = permanent block
    blocked_by TEXT DEFAULT 'system',     -- "system" atau "manual"
    is_active INTEGER DEFAULT 1           -- 1=aktif diblokir, 0=sudah di-unblock
);

-- TABEL 3: traffic_stats — time-series data untuk chart dashboard
CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    packets_per_sec REAL,
    bytes_per_sec REAL,
    alerts_count INTEGER DEFAULT 0,
    flows_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_traffic_stats_timestamp ON traffic_stats(timestamp);

-- TABEL 4: config_history — audit trail perubahan konfigurasi
CREATE TABLE IF NOT EXISTS config_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    changed_at REAL DEFAULT (unixepoch('now','subsec')),
    changed_by TEXT,
    config_key TEXT,
    old_value TEXT,
    new_value TEXT
);

-- TABEL 5: signature_rules — custom rules yang ditambah via API/dashboard
CREATE TABLE IF NOT EXISTS signature_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT UNIQUE NOT NULL,
    name TEXT,
    description TEXT,
    severity TEXT,
    condition_expr TEXT,                  -- Ekspresi kondisi sebagai string Python
    attack_type TEXT,
    is_enabled INTEGER DEFAULT 1,
    created_at REAL DEFAULT (unixepoch('now','subsec'))
);
```

#### 5.8.2 Async SQLAlchemy Setup

```python
# sagedral_ml/database/connection.py

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite+aiosqlite:////var/lib/sagedral-ml/sagedral.db"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def get_db():
    """Dependency injection untuk FastAPI routes."""
    async with AsyncSessionLocal() as session:
        yield session
```

#### 5.8.3 Data Retention Policy (Background Cleanup)

| Tabel | Retensi | Cleanup Jadwal |
|---|---|---|
| `alerts` | 30 hari | Setiap tengah malam |
| `blocked_ips` (is_active=0) | 90 hari | Setiap tengah malam |
| `traffic_stats` | 7 hari | Setiap tengah malam |
| `config_history` | 365 hari | Setiap tengah malam |

---

### 5.9 React Dashboard

**Source**: `sagedral_ml/dashboard/`  
**Build Output**: `sagedral_ml/static/`  
**Diakses melalui**: `http://localhost:8000` (di-serve oleh FastAPI StaticFiles)

#### 5.9.1 Tech Stack Dashboard

| Library | Versi | Fungsi |
|---|---|---|
| React | 18.x | UI Framework |
| Vite | 5.x | Build tool (dev server + bundler) |
| Tailwind CSS | 3.x | Utility-first styling |
| Recharts | 2.x | Chart: Line, Bar, Pie, Area |
| React Router | 6.x | Client-side routing (SPA) |
| Axios | 1.x | HTTP client untuk REST API |
| date-fns | 3.x | Format tanggal dan waktu |
| React Hot Toast | 2.x | Toast notifikasi untuk alert baru |

#### 5.9.2 Halaman dan Komponen

**Halaman 1: Overview (`/`)**

Layout: sidebar kiri + main content area

Komponen yang diperlukan:
- `StatsCard` x4: Total Packets (24h), Total Alerts (24h), Blocked IPs (aktif), Threats Blocked (24h)
- `TrafficChart` (Recharts LineChart): packets/sec dan bytes/sec, data dari WebSocket, window 5 menit terakhir
- `RecentAlertsTable`: 10 alert terbaru, kolom: time, src_ip, attack_type, severity badge, action
- `AttackTypePieChart` (Recharts PieChart): distribusi tipe serangan 24 jam terakhir
- `StatusBadge`: indicator hijau/merah di header untuk status koneksi WebSocket

---

**Halaman 2: Alerts (`/alerts`)**

Komponen:
- `FilterBar`: dropdown severity, dropdown attack_type, date range picker, input IP search
- `AlertsDataTable`: tabel full dengan pagination, semua kolom AlertEvent
  - Klik row -> buka `AlertDetailModal`
- `AlertDetailModal`: tampilkan semua field + tombol "Block IP" (jika belum diblokir)
- `ExportCSVButton`: export tabel yang sedang ditampilkan ke CSV

---

**Halaman 3: Blocked IPs (`/blocked-ips`)**

Komponen:
- `BlockedIPsTable`: kolom IP, alasan, waktu block, auto-unblock countdown, tombol Unblock
- `ManualBlockForm`: input IP, textarea alasan, selector durasi (15m/1h/24h/permanent)
- `WhitelistSection`: daftar IP yang tidak bisa diblokir, tombol tambah/hapus

---

**Halaman 4: Traffic Analysis (`/traffic`)**

Komponen:
- `TimeRangeSelector`: button group 1h/6h/24h/7d
- `TrafficAreaChart` (Recharts AreaChart): volume traffic dalam time range
- `AlertsBarChart` (Recharts BarChart): jumlah alert per jam
- `TopTalkersTable`: top 10 IP dengan traffic/alert terbanyak

---

**Halaman 5: Settings (`/settings`)**

Komponen:
- `CaptureSettingsForm`: interface input, BPF filter
- `DetectionSettingsForm`: threshold sliders untuk alert_threshold, block_threshold, bobot signature/ML
- `IPSSettingsForm`: toggle IPS, pilih backend, whitelist editor, auto-unblock duration
- `SignatureRulesManager`: tabel semua rules, toggle is_enabled, tambah custom rule (form)
- `SaveConfigButton`: PUT ke `/api/v1/config`

---

**Halaman 6: Model Info (`/model`)**

Komponen:
- `ModelInfoCard`: versi, tanggal training, jumlah fitur, akurasi, F1 score
- `FeatureImportanceChart` (Recharts HorizontalBarChart): 20 fitur terpenting dari model
- `RetrainButton`: (jika retrain diaktifkan di config)

#### 5.9.3 WebSocket Client Hook

```javascript
// sagedral_ml/dashboard/src/hooks/useWebSocket.js

import { useEffect, useRef, useState, useCallback } from 'react';

export function useWebSocket(url) {
  const ws = useRef(null);
  const [connected, setConnected] = useState(false);
  const [lastAlert, setLastAlert] = useState(null);
  const [trafficStats, setTrafficStats] = useState(null);
  const [systemStatus, setSystemStatus] = useState(null);

  const connect = useCallback(() => {
    ws.current = new WebSocket(url);

    ws.current.onopen = () => {
      setConnected(true);
      console.log('WebSocket connected');
    };

    ws.current.onclose = () => {
      setConnected(false);
      console.log('WebSocket disconnected, retrying in 3s...');
      setTimeout(connect, 3000);  // Auto-reconnect
    };

    ws.current.onerror = (err) => {
      console.error('WebSocket error:', err);
    };

    ws.current.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.event === 'new_alert') setLastAlert(msg.data);
        if (msg.event === 'traffic_stats') setTrafficStats(msg.data);
        if (msg.event === 'system_status') setSystemStatus(msg.data);
      } catch (e) {
        console.error('Failed to parse WebSocket message:', e);
      }
    };
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      if (ws.current) ws.current.close();
    };
  }, [connect]);

  return { connected, lastAlert, trafficStats, systemStatus };
}
```

#### 5.9.4 Dashboard Build & Deploy

```bash
# Development (gunakan Vite dev server)
cd sagedral_ml/dashboard
npm install
npm run dev
# Dashboard: http://localhost:5173
# API (sudah berjalan): http://localhost:8000

# Production build
npm run build
# Output: sagedral_ml/static/
# FastAPI serve otomatis dari sagedral_ml/static/
```

```python
# sagedral_ml/api/main.py
from fastapi.staticfiles import StaticFiles
import os

static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
```

---

## 6. Data Flow & Lifecycle

### 6.1 Normal Packet Flow (No Threat)

```
Packet diterima oleh NIC
  -> PacketCapture._packet_handler(packet) -> packet_queue.put_nowait(packet)
  -> ProcessingThread: packet = packet_queue.get()
  -> FlowAggregator.process_packet(packet)
     -> [Flow belum selesai] -> update FlowRecord, kembali tunggu
     -> [Flow selesai] -> flow_queue.put(flow_record)
  -> flow_record = flow_queue.get()
  -> feature_vector = flow_record.to_feature_vector()
  -> SignatureEngine.evaluate(feature_vector) -> SignatureResult(matched=False, score=0.0)
  -> MLEngine.predict(feature_vector) -> MLResult(is_anomaly=False, anomaly_score=0.1)
  -> DecisionEngine.decide(sig, ml) -> DecisionResult(action="ALLOW", is_threat=False)
  -> [Tidak ada alert, tidak ada IPS action]
  -> traffic_stats diupdate di memory -> INSERT ke SQLite setiap 60 detik
```

### 6.2 Threat Detected Flow

```
Packet diterima -> ... -> FlowRecord selesai
  -> feature_vector = flow_record.to_feature_vector()
  -> SignatureEngine: SIG-001 matched (SYN Flood, severity=HIGH, score=0.75)
  -> MLEngine: anomaly_score=0.92 > threshold(0.7), is_anomaly=True, attack_class="DDoS"
  -> DecisionEngine:
       final_score = (0.4 * 0.75) + (0.6 * 0.92) = 0.852
       SIG HIGH -> action = "BLOCK"
  -> IPSModule.execute(action="BLOCK", ip="192.168.1.100"):
       -> is_whitelisted("192.168.1.100") -> False, lanjut
       -> block_ip_nftables("192.168.1.100") -> sukses
       -> INSERT INTO blocked_ips VALUES (...)
  -> AlertEvent dibuat (UUID, semua metadata)
  -> alert_queue.put(alert_event)
  -> INSERT INTO alerts VALUES (...)
  -> FastAPI WebSocket task: alert_queue.get() -> broadcast JSON ke semua client
  -> React Dashboard:
       -> menerima {"event":"new_alert", "data":{...}}
       -> toast.error("DDoS detected from 192.168.1.100")
       -> update stats cards
       -> refresh alerts table
```

### 6.3 Auto-Unblock Background Task

```
Background asyncio task (loop setiap 60 detik):
  -> SELECT ip FROM blocked_ips 
       WHERE is_active=1 AND auto_unblock_at IS NOT NULL AND auto_unblock_at <= unixepoch('now')
  -> Untuk setiap IP yang ditemukan:
       -> IPSModule.unblock(ip)
       -> UPDATE blocked_ips SET is_active=0 WHERE ip=?
       -> WebSocket broadcast: {"event": "ip_unblocked", "data": {"ip": "..."}}
       -> Log INFO
```

### 6.4 Traffic Stats Collection

```
Background thread (setiap 10 detik):
  -> Hitung packets_per_sec dan bytes_per_sec dari counter in-memory
  -> Reset counter
  -> INSERT INTO traffic_stats VALUES (...)
  -> WebSocket broadcast traffic_stats event ke semua client
```

---

## 7. API Contract

### 7.1 Format Standar

- Semua request/response: **JSON** (`Content-Type: application/json`)
- Semua timestamp: **Unix timestamp** (float, detik sejak Unix epoch 1970-01-01)
- Error response:

```json
{
  "error": "ERROR_CODE_UPPERCASE",
  "message": "Deskripsi error yang dapat dibaca manusia",
  "detail": "Technical detail (opsional, untuk debugging)"
}
```

### 7.2 HTTP Status Codes

| Code | Kondisi |
|---|---|
| 200 | Operasi berhasil |
| 201 | Resource baru berhasil dibuat |
| 400 | Request tidak valid (input salah format) |
| 403 | Forbidden (contoh: mencoba block IP di whitelist) |
| 404 | Resource tidak ditemukan |
| 409 | Conflict (contoh: IP sudah diblokir) |
| 422 | Validation error dari Pydantic schema |
| 500 | Internal server error (bug di server) |

### 7.3 Authentication

**v1.0**: Tidak ada authentication. Diasumsikan dashboard hanya diakses dari localhost atau trusted internal network.

**v2.0 (future)**: API key via request header `X-API-Key: <key>`.

---

## 8. Database Schema

Lihat detail lengkap di [Section 5.8](#58-database-layer-sqlite).

### Ringkasan Data Retention

| Tabel | Retensi | Keterangan |
|---|---|---|
| `alerts` | 30 hari | Hapus alert lama setiap malam |
| `blocked_ips` (is_active=0) | 90 hari | Simpan history block untuk audit |
| `traffic_stats` | 7 hari | Data granular, tidak perlu lama |
| `config_history` | 365 hari | Audit trail penting |
| `signature_rules` | Permanen | Custom rules tidak dihapus otomatis |

---

## 9. Configuration System

### 9.1 File Lokasi dan Prioritas

```
Prioritas (tinggi ke rendah):
1. Environment variables (SAGEDRAL_*)
2. ~/.config/sagedral/config.toml  <- User config
3. /etc/sagedral/config.toml       <- System config (default)
```

### 9.2 Full Configuration Schema

```toml
# /etc/sagedral/config.toml
# Konfigurasi SAGEDRAL-ML v1.0

[general]
log_level = "INFO"                      # DEBUG, INFO, WARNING, ERROR, CRITICAL
log_file = "/var/log/sagedral-ml.log"   # Path ke log file
data_dir = "/var/lib/sagedral-ml"       # Direktori data utama

[capture]
interface = "eth0"          # WAJIB: nama network interface yang akan dipantau
bpf_filter = ""             # BPF filter (kosong = tangkap semua packet)
promiscuous = true          # Aktifkan promiscuous mode untuk tangkap semua traffic
queue_maxsize = 10000       # Ukuran maksimum packet queue

[feature_extraction]
flow_timeout = 60           # Detik sebelum flow dianggap selesai karena tidak ada aktivitas
max_packets_per_flow = 1000 # Batas maksimum packet per flow sebelum di-forcecomplete

[signature]
enabled = true
custom_rules_file = ""      # Path ke file Python berisi SIGNATURE_RULES tambahan
disabled_rules = []         # Rule ID yang dinonaktifkan: contoh ["SIG-002"]

[ml]
enabled = true
anomaly_threshold = 0.7     # Score >= ini = anomaly (0.0-1.0)
classifier_threshold = 0.6  # Min confidence untuk hasil classifier
model_dir = "/var/lib/sagedral-ml/models"
retrain_on_startup = false

[decision]
alert_threshold = 0.5       # final_score >= ini -> buat alert (tidak block)
block_threshold = 0.7       # final_score >= ini -> block IP
weight_signature = 0.4      # Bobot signature dalam final_score
weight_ml = 0.6             # Bobot ML dalam final_score
dedup_window = 300          # Detik untuk skip alert duplikat dari IP yang sama

[ips]
enabled = true
preferred_backend = "nftables"   # "nftables" atau "iptables"
auto_unblock_after = 3600        # Detik sebelum auto-unblock (0 = permanent)
whitelist = [
    "127.0.0.1",
    "::1",
]

[api]
host = "0.0.0.0"
port = 8000
cors_origins = ["http://localhost:5173", "http://localhost:3000"]

[database]
path = "/var/lib/sagedral-ml/sagedral.db"
retention_days_alerts = 30
retention_days_traffic = 7
```

### 9.3 Environment Variable Override

Format: `SAGEDRAL_<SECTION>_<KEY>=value` (case-insensitive)

Contoh:
```bash
export SAGEDRAL_CAPTURE_INTERFACE=wlan0
export SAGEDRAL_API_PORT=9000
export SAGEDRAL_IPS_ENABLED=false
export SAGEDRAL_DECISION_BLOCK_THRESHOLD=0.8
```

---

## 10. Packaging & Installation

### 10.1 Project Directory Structure

```
sagedral-ml/                         <- Root repository
  pyproject.toml
  README.md
  prd.md
  LICENSE
  .github/
    workflows/
      ci.yml                         <- GitHub Actions: test on push
      publish.yml                    <- GitHub Actions: publish to PyPI on tag
  scripts/
    install.sh                       <- One-line bash installer
    uninstall.sh
  sagedral_ml/                       <- Main Python package
    __init__.py
    __main__.py                      <- Entry: python -m sagedral_ml
    cli.py                           <- Click CLI commands
    main.py                          <- Orchestrator: start semua thread
    config.py                        <- TOML config loader + env override
    capture/
      __init__.py
      sniffer.py                     <- PacketCapture class
    features/
      __init__.py
      extractor.py                   <- FlowAggregator class
      models.py                      <- FlowRecord dataclass
    detection/
      __init__.py
      signature_engine.py            <- SignatureEngine class
      ml_engine.py                   <- MLEngine class
      decision_engine.py             <- DecisionEngine class
      rules/
        __init__.py
        default_rules.py             <- SIGNATURE_RULES list
    ips/
      __init__.py
      response.py                    <- IPSModule class (block/unblock)
    api/
      __init__.py
      main.py                        <- FastAPI app creation + startup
      routers/
        alerts.py                    <- GET /api/v1/alerts
        blocked_ips.py               <- GET/POST/DELETE /api/v1/blocked-ips
        traffic.py                   <- GET /api/v1/traffic/stats
        config.py                    <- GET/PUT /api/v1/config
        model.py                     <- GET /api/v1/model/info
        rules.py                     <- POST /api/v1/rules
      schemas/
        alert.py                     <- Pydantic: AlertResponse, AlertListResponse
        blocked_ip.py                <- Pydantic: BlockedIPResponse, BlockIPRequest
        config.py                    <- Pydantic: ConfigResponse, ConfigUpdateRequest
      websocket.py                   <- WebSocket connection manager + broadcast
    database/
      __init__.py
      connection.py                  <- SQLAlchemy async engine setup
      models.py                      <- SQLAlchemy ORM models
      crud.py                        <- Async CRUD operations
    static/                          <- React build output (JANGAN EDIT MANUAL)
      .gitkeep
    dashboard/                       <- React source code
      package.json
      vite.config.js
      tailwind.config.js
      src/
        main.jsx
        App.jsx
        api/
          client.js                  <- Axios instance + API functions
        hooks/
          useWebSocket.js
          useAlerts.js
          useBlockedIPs.js
        components/
          Layout.jsx
          Sidebar.jsx
          Header.jsx
          StatsCard.jsx
          AlertsTable.jsx
          AlertDetailModal.jsx
          TrafficChart.jsx
          SeverityBadge.jsx
          BlockIPForm.jsx
        pages/
          Overview.jsx
          Alerts.jsx
          BlockedIPs.jsx
          Traffic.jsx
          Settings.jsx
          ModelInfo.jsx
    scripts/
      train_model.py                 <- Script training LightGBM
      evaluate_model.py              <- Script evaluasi model
      download_dataset.py            <- Script download CICIDS dataset
```

### 10.2 pyproject.toml

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "sagedral-ml"
version = "1.0.0"
description = "Smart Adaptive Guardian for Enhanced Detection, Response, and Adaptive Learning - ML NIDPS"
readme = "README.md"
license = { text = "MIT" }
requires-python = ">=3.10"
keywords = ["nids", "nidps", "intrusion-detection", "machine-learning", "network-security", "ips"]
classifiers = [
    "Programming Language :: Python :: 3",
    "Operating System :: POSIX :: Linux",
    "Topic :: System :: Networking :: Monitoring",
    "Topic :: Security",
]

dependencies = [
    "scapy>=2.5.0",
    "lightgbm>=4.0.0",
    "numpy>=1.24.0",
    "pandas>=2.0.0",
    "fastapi>=0.111.0",
    "uvicorn[standard]>=0.29.0",
    "sqlalchemy[asyncio]>=2.0.0",
    "aiosqlite>=0.19.0",
    "click>=8.1.0",
    "tomli-w>=1.0.0",
    "scikit-learn>=1.3.0",
    "dpkt>=1.9.8",
    "psutil>=5.9.0",
    "joblib>=1.3.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.23.0",
    "httpx>=0.27.0",
    "pytest-cov>=4.1.0",
    "ruff>=0.4.0",
    "mypy>=1.8.0",
]
train = [
    "matplotlib>=3.7.0",
    "seaborn>=0.12.0",
    "jupyter>=1.0.0",
]

[project.scripts]
sagedral-ml = "sagedral_ml.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["sagedral_ml"]
artifacts = ["sagedral_ml/static/**"]  # Include built React dashboard
```

### 10.3 CLI Commands (Click)

```bash
# =========== SERVICE MANAGEMENT ===========
sagedral-ml start                     # Mulai semua service (foreground)
sagedral-ml start --daemon            # Mulai sebagai daemon (background)
sagedral-ml stop                      # Hentikan service
sagedral-ml status                    # Tampilkan status lengkap
sagedral-ml restart                   # Stop + Start

# =========== CONFIGURATION ===========
sagedral-ml config show               # Tampilkan konfigurasi aktif (JSON format)
sagedral-ml config template           # Output template config.toml ke stdout
sagedral-ml config validate           # Validasi config file, exit 1 jika ada error
sagedral-ml config set <key> <value>  # Set nilai: sagedral-ml config set capture.interface wlan0

# =========== IP MANAGEMENT ===========
sagedral-ml block <ip>                                # Block IP permanent
sagedral-ml block <ip> --duration 3600               # Block IP selama 1 jam
sagedral-ml unblock <ip>                             # Unblock IP
sagedral-ml whitelist add <ip>                       # Tambah IP ke whitelist
sagedral-ml whitelist remove <ip>                    # Hapus IP dari whitelist
sagedral-ml whitelist show                           # Tampilkan whitelist

# =========== ALERTS ===========
sagedral-ml alerts list                              # Lihat 20 alert terbaru
sagedral-ml alerts list --limit 50 --severity HIGH  # Filter alert
sagedral-ml alerts clear                             # Hapus semua alert (HATI-HATI)

# =========== MODEL ===========
sagedral-ml model info                               # Info model yang terpasang
sagedral-ml model train --dataset /path/to/data.csv  # Train model baru
sagedral-ml model evaluate                           # Evaluasi model pada test set

# =========== SETUP ===========
sagedral-ml install                                  # Setup systemd + nftables + direktori
sagedral-ml uninstall                                # Hapus service + config (tapi tidak data)
sagedral-ml uninstall --purge                        # Hapus semua termasuk database
```

### 10.4 Installer Script (`scripts/install.sh`)

```bash
#!/bin/bash
# SAGEDRAL-ML Installer
# Usage: curl -sSL https://raw.githubusercontent.com/.../install.sh | sudo bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

echo "================================================"
echo "  SAGEDRAL-ML Installer v1.0.0"
echo "  Smart Adaptive Guardian (NIDPS)"
echo "================================================"

# 1. Cek root
[[ $EUID -ne 0 ]] && error "Installer harus dijalankan sebagai root: sudo bash install.sh"

# 2. Cek OS
source /etc/os-release
info "OS: $PRETTY_NAME"

# 3. Install system dependencies
info "Installing system dependencies..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y python3-pip python3-dev libpcap-dev nftables tcpdump
elif command -v yum &>/dev/null; then
    yum install -y python3-pip python3-devel libpcap-devel nftables tcpdump
else
    warn "Package manager tidak dikenali. Install manual: python3-pip libpcap-dev nftables"
fi

# 4. Install sagedral-ml Python package
info "Installing sagedral-ml..."
pip install sagedral-ml

# 5. Buat direktori
info "Creating directories..."
mkdir -p /var/lib/sagedral-ml/models
mkdir -p /etc/sagedral
mkdir -p /var/log

# 6. Config template
if [[ ! -f /etc/sagedral/config.toml ]]; then
    sagedral-ml config template > /etc/sagedral/config.toml
    info "Config template dibuat: /etc/sagedral/config.toml"
    warn "PENTING: Edit /etc/sagedral/config.toml dan set capture.interface!"
else
    info "Config sudah ada, skip."
fi

# 7. Setup nftables
info "Setting up nftables table..."
nft add table inet sagedral 2>/dev/null || true
nft add set inet sagedral blocklist "{ type ipv4_addr; }" 2>/dev/null || true
nft add chain inet sagedral input "{ type filter hook input priority 0; }" 2>/dev/null || true
nft add rule inet sagedral input ip saddr @blocklist drop 2>/dev/null || true
info "nftables setup selesai."

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
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sagedral-ml

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sagedral-ml
info "Systemd service installed and enabled."

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  Instalasi SAGEDRAL-ML selesai!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "Langkah selanjutnya:"
echo "  1. Edit config:   nano /etc/sagedral/config.toml"
echo "     -> Set capture.interface ke nama interface Anda (cek: ip link show)"
echo "  2. Mulai service: systemctl start sagedral-ml"
echo "  3. Cek status:    sagedral-ml status"
echo "  4. Buka dashboard: http://localhost:8000"
echo ""
```

### 10.5 Systemd Service

```ini
# /etc/systemd/system/sagedral-ml.service

[Unit]
Description=SAGEDRAL-ML Network Intrusion Detection and Prevention System
Documentation=https://github.com/your-repo/sagedral-ml
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/var/lib/sagedral-ml

# Validasi config sebelum start
ExecStartPre=/usr/local/bin/sagedral-ml config validate

# Start service
ExecStart=/usr/local/bin/sagedral-ml start --daemon

# Stop service dengan graceful shutdown
ExecStop=/usr/local/bin/sagedral-ml stop

# Restart policy
Restart=on-failure
RestartSec=15
StartLimitBurst=3
StartLimitInterval=120s

# Timeout
TimeoutStartSec=30
TimeoutStopSec=30

# Security (root diperlukan untuk Scapy dan nftables)
NoNewPrivileges=no
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sagedral-ml

[Install]
WantedBy=multi-user.target
```

---

## 11. Non-Functional Requirements

### 11.1 Performance Targets

| Metrik | Target Minimum | Catatan |
|---|---|---|
| Packet capture rate | >= 10,000 pkt/detik | Pada Core i3, 4GB RAM |
| Feature extraction latency | < 100ms per flow | Dari packet terakhir ke FlowRecord selesai |
| ML inference latency | < 50ms per flow | LightGBM sangat cepat untuk inference |
| Alert end-to-end latency | < 2 detik | Dari packet pertama sampai notifikasi di dashboard |
| Memory usage (total proses) | < 500 MB | Termasuk model ML di memori |
| CPU usage (idle/low traffic) | < 5% | Core i3 |
| CPU usage (high traffic) | < 40% | Core i3, 10K pkt/detik |
| Dashboard load time | < 2 detik | Initial page load |
| API response time | < 200ms | p95 untuk semua REST endpoints |

### 11.2 Reliability Requirements

| Aspek | Requirement | Implementasi |
|---|---|---|
| Target uptime | 99.5% | Systemd auto-restart |
| Graceful shutdown | Simpan state sebelum exit | signal handler SIGTERM |
| Capture crash recovery | Restart otomatis, max 3x/5 menit | Supervisor thread |
| Queue overflow | Drop dengan log, jangan crash | try/except put_nowait |
| DB write failure | Log ke file, tetap jalankan detection | try/except di crud |
| nftables failure | Fallback ke iptables, log warning | Automatic backend switch |

### 11.3 Code Quality Requirements

- Semua modul Python harus memiliki **module-level docstring**
- Semua kelas publik harus memiliki **class docstring**
- Semua fungsi/method publik harus memiliki **type hints** Python 3.10+
- Unit test coverage >= **70%** secara keseluruhan
- Semua magic numbers (0.7, 1000, dll) harus menggunakan **konstanta bernama**
- Semua log messages harus menggunakan **level yang tepat**: DEBUG (detail), INFO (normal), WARNING (masalah tapi bisa lanjut), ERROR (error tapi tidak crash), CRITICAL (crash/tidak bisa lanjut)

### 11.4 Compatibility Matrix

| Aspek | Requirement |
|---|---|
| Python version | 3.10, 3.11, 3.12 (test di semua versi) |
| Linux distributions | Ubuntu 20.04+, Debian 11+, CentOS 8+, RHEL 8+, Arch Linux |
| CPU architecture | x86_64, ARM64 (Raspberry Pi compatible) |
| Network protocol | IPv4 (IPv6 partial support: future v1.1) |
| Browser (dashboard) | Chrome 90+, Firefox 88+, Safari 14+, Edge 90+ |

---

## 12. Security Considerations

### 12.1 Privilege Management

- Proses utama harus berjalan sebagai **root** (diperlukan untuk Scapy raw socket dan nftables)
- v1.0 akzeptabel karena ini adalah security tool
- v2.0 (future): pisahkan dengan Linux capabilities (CAP_NET_RAW untuk capture, CAP_NET_ADMIN untuk IPS)

### 12.2 Input Validation — WAJIB UNTUK SEMUA INPUT YANG MASUK KE SUBPROCESS

```python
# sagedral_ml/ips/response.py

import ipaddress

def validate_ip(ip: str) -> str:
    """
    Validasi dan sanitasi IP address sebelum digunakan di subprocess command.
    Raise ValueError jika IP tidak valid.
    SELALU panggil fungsi ini sebelum menggunakan IP di subprocess.run()
    """
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise ValueError(f"IP address tidak valid: '{ip}'. Hanya format IPv4/IPv6 yang diterima.")
```

### 12.3 Command Injection Prevention

**DILARANG KERAS** — Jangan pernah lakukan ini:
```python
# SALAH - BERBAHAYA - COMMAND INJECTION POSSIBLE
subprocess.run(f"nft add element inet sagedral blocklist {{ {ip} }}", shell=True)
```

**YANG BENAR** — Selalu gunakan list argument:
```python
# BENAR - AMAN
validated_ip = validate_ip(ip)
subprocess.run(
    ["nft", "add", "element", "inet", "sagedral", "blocklist", f"{{ {validated_ip} }}"],
    capture_output=True,
    timeout=5,
    # TIDAK ADA shell=True
)
```

### 12.4 Whitelist Protection (CRITICAL SAFETY FEATURE)

Ini adalah fitur keselamatan paling penting. Tanpa whitelist, sistem bisa memblokir dirinya sendiri.

**Aturan hardcoded (tidak bisa di-override oleh config):**
- `127.0.0.1` (IPv4 loopback) — TIDAK BOLEH DIBLOKIR
- `::1` (IPv6 loopback) — TIDAK BOLEH DIBLOKIR

**Deteksi gateway otomatis saat startup:**
```python
import subprocess, re

def get_default_gateway() -> str | None:
    """Dapatkan IP default gateway dari route table."""
    try:
        result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
        match = re.search(r"default via (\S+)", result.stdout)
        return match.group(1) if match else None
    except Exception:
        return None
```

**Urutan pengecekan whitelist:**
1. Cek IP == "127.0.0.1" atau "::1" (hardcoded)
2. Cek IP ada di `config.ips.whitelist` (dari config file)
3. Cek IP == default gateway (dari route table, dideteksi saat startup)

### 12.5 API Security

- Dashboard diakses melalui `localhost:8000` by default
- CORS dikonfigurasi secara eksplisit (tidak menggunakan `allow_origins=["*"]` di production)
- Semua POST/PUT/DELETE endpoint menggunakan Pydantic untuk validasi input
- Rate limiting (future v1.1): gunakan `slowapi` library

### 12.6 Logging Security

- JANGAN log payload packet atau konten data pengguna
- Log IP address adalah normal dan diperlukan untuk audit
- Log file di `/var/log/sagedral-ml.log` harus memiliki permission `640` (root:root)

---

## 13. Directory Structure (System Paths)

```
/etc/sagedral/
  config.toml                  <- Konfigurasi utama (edit setelah install)
  custom_rules.py              <- Custom signature rules (opsional, buat sendiri)

/var/lib/sagedral-ml/
  sagedral.db                  <- SQLite database (JANGAN hapus manual)
  models/
    anomaly_detector.pkl       <- Model anomaly detection (binary LightGBM)
    attack_classifier.pkl      <- Model attack classification (multiclass LightGBM)
    feature_names.json         <- Urutan 28 nama fitur yang harus konsisten

/var/log/
  sagedral-ml.log              <- Log file utama

/etc/systemd/system/
  sagedral-ml.service          <- Systemd service file

/usr/local/bin/
  sagedral-ml                  <- Executable CLI (dari pip install)
```

---

## 14. Glossary

| Istilah | Definisi |
|---|---|
| **NIDPS** | Network Intrusion Detection and Prevention System — sistem yang mendeteksi DAN mencegah intrusi |
| **NIDS** | Network Intrusion Detection System — hanya deteksi, tidak ada prevention |
| **IPS** | Intrusion Prevention System — komponen yang aktif memblokir ancaman |
| **Flow** | Sekumpulan packet jaringan yang memiliki 5-tuple sama dalam jendela waktu tertentu |
| **5-tuple** | Pengidentifikasi unik sebuah flow: `(src_ip, dst_ip, src_port, dst_port, protocol)` |
| **Signature** | Pola serangan yang sudah diketahui, didefinisikan sebagai aturan eksplisit (rule-based) |
| **Anomaly** | Perilaku jaringan yang menyimpang dari pola normal, dideteksi oleh ML |
| **BPF Filter** | Berkeley Packet Filter — bahasa query untuk memfilter packet di level kernel |
| **nftables** | Framework packet filtering modern di Linux, pengganti iptables |
| **LightGBM** | Light Gradient Boosting Machine — algoritma ML tree-based yang cepat dan hemat memory |
| **WebSocket** | Protokol komunikasi full-duplex (dua arah) yang berjalan di atas TCP |
| **Promiscuous Mode** | Mode network card yang menangkap SEMUA packet di jaringan, bukan hanya yang ditujukan ke host ini |
| **AlertEvent** | Dataclass Python yang merepresentasikan satu deteksi ancaman dengan semua metadata |
| **FlowRecord** | Dataclass Python yang merepresentasikan satu network flow beserta 28 fitur statistiknya |
| **Decision Engine** | Komponen yang menggabungkan hasil Signature + ML untuk menghasilkan keputusan ALLOW/ALERT/BLOCK |
| **Whitelist** | Daftar IP yang tidak boleh diblokir oleh sistem (proteksi dari self-blocking) |
| **Deduplication** | Mekanisme untuk tidak membuat alert yang sama berulang-ulang dalam window waktu tertentu |
| **IAT** | Inter-Arrival Time — jarak waktu antara dua packet berurutan dalam satu flow |
| **CICIDS** | Canadian Institute for Cybersecurity Intrusion Detection Evaluation Dataset |

---

## Appendix A: Urutan Implementasi — Panduan Lengkap

### Untuk Junior Developer / AI Agent

Implementasikan DALAM URUTAN INI. Selesaikan dan test setiap fase sebelum ke fase berikutnya.

#### Fase 1: Foundation (Estimasi: 2-3 hari)

**Tujuan**: Setup project dan buat fondasi data layer.

- [ ] Inisialisasi repository dengan struktur direktori sesuai Section 10.1
- [ ] Buat `pyproject.toml` sesuai Section 10.2
- [ ] Implementasikan `sagedral_ml/config.py`:
  - Load `/etc/sagedral/config.toml` dengan `tomllib` (Python 3.11+) atau `tomli`
  - Override dengan environment variable `SAGEDRAL_*`
  - Expose sebagai singleton `get_config()` function
- [ ] Implementasikan `sagedral_ml/database/connection.py` (async SQLAlchemy setup)
- [ ] Implementasikan `sagedral_ml/database/models.py` (SQLAlchemy ORM models)
- [ ] Implementasikan `sagedral_ml/database/crud.py` (async CRUD operations)
- [ ] Implementasikan `sagedral_ml/features/models.py` (FlowRecord dataclass + `to_feature_vector()`)
- [ ] Buat `tests/test_config.py` dan `tests/test_database.py`
- [ ] Verifikasi: semua test fase 1 pass

#### Fase 2: Detection Core (Estimasi: 3-4 hari)

**Tujuan**: Implementasikan mesin deteksi hybrid.

- [ ] Implementasikan `sagedral_ml/detection/rules/default_rules.py` (min 7 rules)
- [ ] Implementasikan `sagedral_ml/detection/signature_engine.py`:
  - Method `evaluate(feature_vector: dict) -> SignatureResult`
  - Handle disabled_rules dari config
  - Handle custom rules dari file
- [ ] Implementasikan `sagedral_ml/detection/ml_engine.py`:
  - Load model dengan `joblib.load()` di `__init__`
  - Method `predict(feature_vector: dict) -> MLResult`
  - Graceful fallback jika model tidak ada
- [ ] Implementasikan `sagedral_ml/detection/decision_engine.py`:
  - Method `decide(sig_result, ml_result, src_ip, flow_record) -> DecisionResult`
  - Implementasikan scoring formula
  - Implementasikan deduplication cache
- [ ] Implementasikan `sagedral_ml/features/extractor.py` (FlowAggregator):
  - `process_packet(packet)` — parse dan update flow
  - `cleanup_timeouts()` — cek flow yang expired
  - Thread-safe dengan `threading.Lock()`
- [ ] Buat `tests/test_signature_engine.py`, `tests/test_ml_engine.py`, `tests/test_decision_engine.py`
- [ ] Buat `tests/fixtures/mock_flows.py` dengan minimal 5 mock flows (normal + berbagai serangan)
- [ ] Verifikasi: semua test fase 2 pass

#### Fase 3: Capture & IPS (Estimasi: 2-3 hari)

**Tujuan**: Implementasikan capture packet dan tindakan IPS.

- [ ] Implementasikan `sagedral_ml/capture/sniffer.py` (PacketCapture class)
- [ ] Implementasikan `sagedral_ml/ips/response.py`:
  - `block_ip(ip: str) -> bool` — pilih nftables atau iptables
  - `unblock_ip(ip: str) -> bool`
  - `is_whitelisted(ip: str) -> bool`
  - `setup_nftables_table()` — setup table saat startup
- [ ] Buat AlertEvent dataclass di `sagedral_ml/ips/models.py`
- [ ] Manual test di Linux VM: jalankan sniffer, tangkap packet, cek FlowRecord terbentuk
- [ ] Verifikasi: block IP berfungsi di nftables (`nft list ruleset` untuk cek)

#### Fase 4: Backend API (Estimasi: 3-4 hari)

**Tujuan**: Implementasikan REST API dan WebSocket.

- [ ] Implementasikan `sagedral_ml/api/main.py` (FastAPI app, CORS, lifespan handler)
- [ ] Implementasikan `sagedral_ml/api/websocket.py` (ConnectionManager class untuk broadcast)
- [ ] Implementasikan semua Pydantic schemas di `sagedral_ml/api/schemas/`
- [ ] Implementasikan routers:
  - [ ] `routers/alerts.py` — GET /api/v1/alerts dengan filter dan pagination
  - [ ] `routers/blocked_ips.py` — GET, POST, DELETE
  - [ ] `routers/traffic.py` — GET /api/v1/traffic/stats
  - [ ] `routers/config.py` — GET, PUT /api/v1/config
  - [ ] `routers/model.py` — GET /api/v1/model/info
  - [ ] `routers/rules.py` — POST /api/v1/rules
- [ ] Background task: broadcast traffic_stats via WebSocket setiap 5 detik
- [ ] Background task: auto-unblock IP yang sudah expired setiap 60 detik
- [ ] Buat `tests/test_api.py` dengan httpx AsyncClient
- [ ] Verifikasi: semua API endpoints return response yang benar

#### Fase 5: Dashboard (Estimasi: 4-5 hari)

**Tujuan**: Bangun React dashboard yang berfungsi penuh.

- [ ] Setup Vite + React + Tailwind + Recharts di `sagedral_ml/dashboard/`
- [ ] Implementasikan `api/client.js` (Axios instance + semua API function)
- [ ] Implementasikan `hooks/useWebSocket.js` (lihat Section 5.9.3)
- [ ] Implementasikan komponen shared: Layout, Sidebar, Header, StatsCard, SeverityBadge
- [ ] Implementasikan halaman Overview (/)
- [ ] Implementasikan halaman Alerts (/alerts) dengan filter dan modal
- [ ] Implementasikan halaman Blocked IPs (/blocked-ips) dengan form block manual
- [ ] Implementasikan halaman Traffic Analysis (/traffic)
- [ ] Implementasikan halaman Settings (/settings)
- [ ] Implementasikan halaman Model Info (/model)
- [ ] `npm run build` -> pastikan output di `sagedral_ml/static/`
- [ ] Verifikasi: buka `http://localhost:8000`, dashboard muncul, WebSocket terhubung

#### Fase 6: Orchestrator & CLI (Estimasi: 2 hari)

**Tujuan**: Hubungkan semua komponen dan buat CLI.

- [ ] Implementasikan `sagedral_ml/main.py`:
  - Start CaptureThread dengan PacketCapture
  - Start ProcessingThread (loop: read packet_queue -> extract -> detect -> decide -> ips)
  - Start FastAPI dengan uvicorn di thread terpisah
  - Handle SIGTERM/SIGINT untuk graceful shutdown
- [ ] Implementasikan `sagedral_ml/cli.py` dengan semua commands di Section 10.3
- [ ] Test end-to-end: `sagedral-ml start` -> buka dashboard -> lihat traffic real
- [ ] Buat `scripts/install.sh` sesuai Section 10.4
- [ ] Buat systemd service file sesuai Section 10.5
- [ ] Test full install di VM Linux bersih

#### Fase 7: Model Training (Estimasi: 2-3 hari)

**Tujuan**: Train model ML dan package bersama distribusi.

- [ ] Buat `sagedral_ml/scripts/download_dataset.py` untuk download CICIDS 2017
- [ ] Buat `sagedral_ml/scripts/train_model.py`:
  - Load dan preprocess dataset
  - Train anomaly detector (binary)
  - Train attack classifier (multiclass)
  - Simpan model ke `/var/lib/sagedral-ml/models/`
  - Simpan `feature_names.json`
  - Print evaluation metrics
- [ ] Buat `sagedral_ml/scripts/evaluate_model.py`:
  - Load model yang sudah disimpan
  - Evaluasi pada test set
  - Print confusion matrix dan classification report
- [ ] Jalankan training dan verifikasi model bekerja dengan `sagedral-ml model info`

---

## Appendix B: Test Cases Lengkap

### B.1 Mock Flow Data

```python
# tests/fixtures/mock_flows.py

MOCK_NORMAL_FLOW = {
    "duration": 5.0,
    "total_fwd_packets": 20, "total_bwd_packets": 18,
    "total_fwd_bytes": 5000, "total_bwd_bytes": 12000,
    "fwd_packet_len_mean": 250.0, "fwd_packet_len_std": 50.0,
    "bwd_packet_len_mean": 666.7, "bwd_packet_len_std": 100.0,
    "flow_bytes_per_sec": 3400.0, "flow_packets_per_sec": 7.6,
    "fwd_iat_mean": 0.25, "fwd_iat_std": 0.1,
    "bwd_iat_mean": 0.28, "bwd_iat_std": 0.12,
    "psh_flag_count": 10, "urg_flag_count": 0,
    "syn_flag_count": 1, "fin_flag_count": 1,
    "rst_flag_count": 0, "ack_flag_count": 38,
    "avg_fwd_segment_size": 250.0, "avg_bwd_segment_size": 666.7,
    "fwd_header_len": 400, "bwd_header_len": 360,
    "down_up_ratio": 2.4,
    "protocol": 6, "dst_port": 80,
}

MOCK_SYN_FLOOD_FLOW = {
    "duration": 1.0,
    "total_fwd_packets": 500, "total_bwd_packets": 0,
    "total_fwd_bytes": 30000, "total_bwd_bytes": 0,
    "fwd_packet_len_mean": 60.0, "fwd_packet_len_std": 5.0,
    "bwd_packet_len_mean": 0.0, "bwd_packet_len_std": 0.0,
    "flow_bytes_per_sec": 30000.0, "flow_packets_per_sec": 500.0,
    "fwd_iat_mean": 0.002, "fwd_iat_std": 0.001,
    "bwd_iat_mean": 0.0, "bwd_iat_std": 0.0,
    "psh_flag_count": 0, "urg_flag_count": 0,
    "syn_flag_count": 500, "fin_flag_count": 0,
    "rst_flag_count": 0, "ack_flag_count": 0,
    "avg_fwd_segment_size": 60.0, "avg_bwd_segment_size": 0.0,
    "fwd_header_len": 10000, "bwd_header_len": 0,
    "down_up_ratio": 0.0,
    "protocol": 6, "dst_port": 80,
}

MOCK_SSH_BRUTEFORCE_FLOW = {
    "duration": 25.0,
    "total_fwd_packets": 100, "total_bwd_packets": 80,
    "total_fwd_bytes": 8000, "total_bwd_bytes": 6000,
    "fwd_packet_len_mean": 80.0, "fwd_packet_len_std": 10.0,
    "bwd_packet_len_mean": 75.0, "bwd_packet_len_std": 8.0,
    "flow_bytes_per_sec": 560.0, "flow_packets_per_sec": 7.2,
    "fwd_iat_mean": 0.25, "fwd_iat_std": 0.1,
    "bwd_iat_mean": 0.31, "bwd_iat_std": 0.09,
    "psh_flag_count": 50, "urg_flag_count": 0,
    "syn_flag_count": 1, "fin_flag_count": 0,
    "rst_flag_count": 0, "ack_flag_count": 178,
    "avg_fwd_segment_size": 80.0, "avg_bwd_segment_size": 75.0,
    "fwd_header_len": 2000, "bwd_header_len": 1600,
    "down_up_ratio": 0.75,
    "protocol": 6, "dst_port": 22,
}
```

### B.2 Test Suite: Signature Engine

```python
# tests/test_signature_engine.py

import pytest
from sagedral_ml.detection.signature_engine import SignatureEngine
from tests.fixtures.mock_flows import MOCK_NORMAL_FLOW, MOCK_SYN_FLOOD_FLOW, MOCK_SSH_BRUTEFORCE_FLOW

class TestSignatureEngine:

    def setup_method(self):
        self.engine = SignatureEngine()

    def test_normal_traffic_not_flagged(self):
        result = self.engine.evaluate(MOCK_NORMAL_FLOW)
        assert result.matched is False
        assert len(result.matched_rules) == 0
        assert result.signature_score == 0.0

    def test_syn_flood_detected_sig001(self):
        result = self.engine.evaluate(MOCK_SYN_FLOOD_FLOW)
        assert result.matched is True
        assert "SIG-001" in result.matched_rules
        assert result.max_severity == "HIGH"
        assert result.signature_score == 0.75

    def test_ssh_bruteforce_detected_sig005(self):
        result = self.engine.evaluate(MOCK_SSH_BRUTEFORCE_FLOW)
        assert result.matched is True
        assert "SIG-005" in result.matched_rules

    def test_disabled_rule_skipped(self):
        self.engine.disabled_rules = ["SIG-001"]
        result = self.engine.evaluate(MOCK_SYN_FLOOD_FLOW)
        assert "SIG-001" not in result.matched_rules

    def test_severity_score_mapping_critical(self):
        # CRITICAL severity -> score 1.0
        # Mock dengan override max_severity
        pass  # implement sesuai implementasi

    def test_multiple_rules_match(self):
        # Flow yang match beberapa rule sekaligus
        # max_severity harus diambil dari rule dengan severity tertinggi
        pass
```

### B.3 Test Suite: API Endpoints

```python
# tests/test_api.py

import pytest
from httpx import AsyncClient
from sagedral_ml.api.main import create_app

@pytest.fixture
async def client():
    app = create_app(test_mode=True)
    async with AsyncClient(app=app, base_url="http://test") as c:
        yield c

@pytest.mark.asyncio
async def test_get_status_returns_200(client):
    r = await client.get("/api/v1/status")
    assert r.status_code == 200
    data = r.json()
    assert "status" in data
    assert "uptime_seconds" in data
    assert "ml_model_loaded" in data

@pytest.mark.asyncio
async def test_get_alerts_returns_pagination(client):
    r = await client.get("/api/v1/alerts?page=1&limit=10")
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "page" in data
    assert "data" in data
    assert isinstance(data["data"], list)

@pytest.mark.asyncio
async def test_block_valid_ip_success(client):
    r = await client.post("/api/v1/blocked-ips", json={
        "ip": "10.99.99.99",
        "reason": "Test block",
        "duration_seconds": 60
    })
    assert r.status_code == 200
    assert r.json()["success"] is True

@pytest.mark.asyncio
async def test_block_localhost_rejected(client):
    r = await client.post("/api/v1/blocked-ips", json={
        "ip": "127.0.0.1",
        "reason": "Should be rejected",
        "duration_seconds": 60
    })
    assert r.status_code == 403
    assert r.json()["error"] == "WHITELISTED"

@pytest.mark.asyncio
async def test_block_invalid_ip_rejected(client):
    r = await client.post("/api/v1/blocked-ips", json={
        "ip": "not-an-ip",
        "reason": "Test",
        "duration_seconds": 60
    })
    assert r.status_code in (400, 422)

@pytest.mark.asyncio
async def test_unblock_ip_success(client):
    # Block dulu
    await client.post("/api/v1/blocked-ips", json={
        "ip": "10.88.88.88", "reason": "test", "duration_seconds": 60
    })
    # Unblock
    r = await client.delete("/api/v1/blocked-ips/10.88.88.88")
    assert r.status_code == 200
    assert r.json()["success"] is True
```

### B.4 Test Coverage Target

| Modul | Target Coverage |
|---|---|
| `sagedral_ml/config.py` | >= 85% |
| `sagedral_ml/features/extractor.py` | >= 80% |
| `sagedral_ml/features/models.py` | >= 90% |
| `sagedral_ml/detection/signature_engine.py` | >= 90% |
| `sagedral_ml/detection/ml_engine.py` | >= 70% |
| `sagedral_ml/detection/decision_engine.py` | >= 85% |
| `sagedral_ml/ips/response.py` | >= 75% |
| `sagedral_ml/api/routers/` | >= 80% |
| `sagedral_ml/database/crud.py` | >= 80% |
| **Total** | **>= 70%** |

---

*Dokumen ini adalah acuan teknis lengkap untuk pengembangan SAGEDRAL-ML v1.0.*  
*Semua perubahan arsitektur HARUS didokumentasikan di dokumen ini sebelum diimplementasikan.*  
*Jika ada yang tidak jelas, lihat kembali ke section yang relevan atau buka GitHub Issues.*

---

**Project**: SAGEDRAL-ML  
**Author**: Hercio Moreira  
**PRD Version**: 1.0.0  
**Architecture Status**: LOCKED — TIDAK BOLEH DIUBAH TANPA REVIEW  
**Development Status**: APPROVED — READY FOR DEVELOPMENT
