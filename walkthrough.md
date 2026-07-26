# Walkthrough SAGEDRAL-ML

Panduan ini berlaku untuk rilis enterprise hasil implementasi `update.md`.

## 1. Prasyarat

- Linux kernel dengan `AF_PACKET`; Ubuntu/BackBox 20.04 direkomendasikan untuk
  runtime Python 3.8.10 bawaan.
- Python 3.8.10 atau lebih baru.
- `libpcap`, `tcpdump`, `nftables`, `libgomp`, dan compiler saat instalasi.
- Node.js 18 hanya diperlukan bila membangun ulang dashboard.

```bash
python3 --version
sudo bash scripts/install.sh
sudo systemctl status sagedral-ml
sagedral-ml health
```

## 2. Konfigurasi awal

Edit `/etc/sagedral/config.toml`.

```toml
[capture]
interface = "eth1"
backend = "scapy"       # scapy | libpcap | af_packet
bpf_filter = ""
promiscuous = true

[ips]
enabled = true
preferred_backend = "nftables"
whitelist = ["127.0.0.1", "::1", "10.20.0.0/16"]

[api]
host = "127.0.0.1"     # gunakan reverse proxy TLS untuk akses eksternal
port = 8000
```

Validasi dan restart:

```bash
sudo -u sagedral sagedral-ml config validate
sudo systemctl restart sagedral-ml
sudo journalctl -u sagedral-ml -f
```

Untuk throughput tinggi, `af_packet` menggunakan TPACKET_V2
`PACKET_RX_RING` mmap dan memasang BPF melalui `tcpdump -ddd`. Pantau
`kernel_drop_rate_pct` pada endpoint capture atau Prometheus.

## 3. Login pertama

```bash
sudo cat /var/lib/sagedral-ml/.sagedral-admin-secret
sagedral-ml login
```

Dashboard dilindungi JWT. Admin dapat membuka menu Jestaun Uzuáriu untuk
membuat `viewer`, `analyst`, atau `admin`. Viewer read-only; analyst dapat
menanggapi alert dan block/unblock; admin mengelola konfigurasi, whitelist,
rules, audit, dan user.

## 4. Endpoint utama

| Method | Path | Akses |
|---|---|---|
| POST | `/api/v1/auth/login` | Publik, rate limited |
| GET | `/api/v1/status` | Publik minimal |
| GET | `/api/v1/status/details` | Login |
| GET | `/api/v1/capture/stats` | Login |
| GET | `/api/v1/alerts` | Login |
| GET | `/api/v1/alerts/export.csv` | Login |
| POST | `/api/v1/alerts/{id}/feedback` | Analyst/Admin |
| POST | `/api/v1/alerts/{id}/close` | Analyst/Admin |
| POST | `/api/v1/blocked-ips/bulk` | Analyst/Admin |
| POST | `/api/v1/blocked-ips/networks` | Admin |
| GET/POST/DELETE | `/api/v1/whitelist` | Login/Admin/Admin |
| GET/POST/PUT/DELETE | `/api/v1/rules` | Login/Admin/Admin/Admin |
| GET/POST/PUT/DELETE | `/api/v1/users` | Admin |
| GET | `/api/v1/audit-logs` | Admin |
| GET | `/api/v1/model/drift` | Login |
| POST | `/api/v1/model/reload` | Admin |
| POST | `/api/v1/feedback/retrain` | Admin |
| GET | `/healthz`, `/readyz`, `/metrics` | Monitoring |
| WS | `/ws/alerts?token=<JWT>` | JWT aktif |

Swagger tersedia di `/docs`.

## 5. Custom signature DSL

Contoh request rule:

```json
{
  "rule_id": "CUSTOM-SSH-01",
  "name": "SSH burst",
  "description": "Banyak koneksi SSH singkat",
  "severity": "HIGH",
  "condition_expr": "flow.get('dst_port', 0) == 22 and total_fwd_packets > 30",
  "attack_type": "BruteForce"
}
```

DSL mendukung operasi numerik, boolean, perbandingan, nama fitur, dan
`flow.get()`. Import, dunder, comprehension, lambda, assignment, dan function
call lain ditolak.

## 6. SIEM, notifikasi, GeoIP

```toml
[siem]
enabled = true
minimum_severity = "MEDIUM"
syslog_host = "10.20.0.30"
syslog_port = 514
syslog_protocol = "tcp"
webhook_urls = ["https://hooks.slack.com/services/..."]

[notifications]
enabled = true
minimum_severity = "HIGH"
telegram_bot_token = "..."
telegram_chat_id = "..."
smtp_host = "smtp.internal"
smtp_port = 587
smtp_starttls = true
smtp_username = "sagedral"
smtp_password = "..."
email_sender = "sagedral@example.internal"
email_recipients = ["soc@example.internal"]
```

Pengiriman SIEM dan notifikasi dilakukan di worker terbatas agar hot loop
deteksi tidak menunggu jaringan eksternal.

## 7. Monitoring dan performance

```bash
curl -f http://127.0.0.1:8000/healthz
curl -f http://127.0.0.1:8000/readyz
curl http://127.0.0.1:8000/metrics
python scripts/benchmark.py --iterations 10000 --minimum-fps 1000
python scripts/pcap_regression.py --self-test
```

Konfigurasi Prometheus dan alert tersedia di `deploy/`. Angka 1 Gbps bukan
jaminan lintas hardware; lakukan soak test pada NIC, kernel, jumlah core,
ukuran flow, dan traffic mix target sebelum inline production.

## 8. TLS dan HA

Template Nginx TLS/CSP: `deploy/nginx-sagedral.conf`.

Template Keepalived: `deploy/keepalived-sagedral.conf`. HA sync memakai shared
secret dan endpoint internal blocklist. Gunakan PostgreSQL shared/replicated,
firewall antar-node terbatas, dan secret minimal 24 karakter.

Prosedur lengkap terdapat di [docs/RUNBOOK.md](docs/RUNBOOK.md).
