# SAGEDRAL-ML

SAGEDRAL-ML adalah NIDPS hibrida untuk Linux: packet capture, agregasi flow,
signature DSL aman, deteksi ML dua tahap, respons IPS `nftables`/`iptables`,
API FastAPI, dashboard React berbahasa Tetun, audit, integrasi SIEM, notifikasi,
adaptive learning, monitoring drift, dan HA active-passive.

Runtime minimum tetap **Python 3.8.10**. Dependensi yang berpotensi memutus
kompatibilitas Python 3.8 diberi batas versi di `pyproject.toml` dan
`requirements.txt`; CI menguji Python 3.8, 3.9, 3.10, dan 3.11.

## Instalasi Linux

```bash
git clone <repository-url> sagedral-ml
cd sagedral-ml
sudo bash scripts/install.sh
```

Installer membuat user non-root `sagedral`, direktori data, konfigurasi,
fallback model, service systemd, dan logrotate. Service memperoleh hanya
`CAP_NET_RAW` dan `CAP_NET_ADMIN`; ia tidak berjalan sebagai root.

Password admin pertama dibuat acak dan disimpan dengan mode `0600`:

```bash
sudo cat /var/lib/sagedral-ml/.sagedral-admin-secret
```

Login ke dashboard di `http://alamat-node:8000`, lalu segera buat akun admin
personal dan amankan/hapus file bootstrap tersebut.

## Pengembangan

```bash
python3.8 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -e ".[dev]"
pytest -q
```

Dashboard:

```bash
cd sagedral_ml/dashboard
npm ci
npm run build
```

Mode API tanpa live capture/firewall:

```bash
sagedral-ml start --no-capture --no-daemon
```

## Perintah penting

```bash
sagedral-ml login
sagedral-ml health
sagedral-ml status
sagedral-ml config validate
sagedral-ml database migrate
sagedral-ml model init
sagedral-ml model info
sagedral-ml train --dataset flows.csv --hot-reload
sagedral-ml backup create
sagedral-ml backup list
sagedral-ml whitelist add 10.20.0.0/16 --note "Rede interna"
sagedral-ml alerts list
```

## Docker

```bash
docker compose build
docker compose up -d
```

Image memakai Python 3.8.10. Config dan data berada di named volume agar update
dari dashboard tetap persisten. Container memerlukan capability `NET_RAW` dan
`NET_ADMIN`, serta `network_mode: host`; gunakan hanya pada host Linux yang
dipercaya.

## Backend enterprise

PostgreSQL bersifat opsional:

```bash
pip install -e ".[postgres]"
```

```toml
[database]
backend = "postgresql"
connection_string = "postgresql+asyncpg://sagedral:password@db/sagedral"
run_migrations = true
```

GeoIP:

```bash
pip install -e ".[geoip]"
```

Aktifkan `geolocation.enabled` dan arahkan `db_path` ke database GeoLite2
Country yang berlisensi untuk organisasi Anda.

## Keamanan API

- OAuth2 password flow dan JWT persisten.
- Role `viewer`, `analyst`, dan `admin`, ditambah permission per aksi.
- Semua endpoint operasional membutuhkan token; `/healthz`, `/readyz`,
  `/metrics`, dan status publik minimal dibiarkan untuk monitoring.
- Secret tidak pernah dikembalikan oleh API konfigurasi.
- Custom rule hanya menerima DSL ekspresi AST terbatas; file Python tidak
  dieksekusi.
- WebSocket membutuhkan JWT aktif, mendukung topic subscription, keepalive,
  dan replay buffer.

Dokumentasi lanjutan:

- [Panduan menjalankan](walkthrough.md)
- [Runbook operasi, DR, dan upgrade](docs/RUNBOOK.md)
- [Status implementasi roadmap](UPDATE_IMPLEMENTATION_STATUS.md)
- [PRD](prd.md)
- [Rencana awal](implementation_plan.md)
- [Topologi dasar](sagedral-ml-topologi-basic.md)
