# Runbook Operasi, Disaster Recovery, dan Upgrade

## Pemeriksaan harian

```bash
sagedral-ml health
sudo systemctl status sagedral-ml
sudo journalctl -u sagedral-ml --since today
curl -s http://127.0.0.1:8000/metrics
sagedral-ml backup list
```

Periksa capture running, packet/kernel drop, backlog alert, block aktif,
drift PSI, ruang filesystem, kegagalan SIEM/notifikasi, dan sinkronisasi HA.

## Respons insiden

1. Jangan menghapus alert sebelum export CSV dan snapshot audit.
2. Verifikasi source, destination, signature, skor ML, GeoIP, dan flow.
3. Analyst memberi label true/false positive atau uncertain.
4. Block manual hanya setelah memeriksa whitelist, gateway, dan IP node.
5. Untuk false positive, tambahkan override per-rule yang sesempit mungkin;
   jangan whitelist subnet besar tanpa approval.
6. Simpan waktu, user, alasan, dan perubahan di tiket insiden. Audit log API
   menjadi bukti tambahan, bukan pengganti tiket.

## Backup

```bash
sudo -u sagedral sagedral-ml backup create \
  --output /var/lib/sagedral-ml/backups/manual-$(date +%F).tar.gz
sudo -u sagedral sagedral-ml backup list
```

SQLite memakai WAL checkpoint lalu gzip. PostgreSQL memakai `pg_dump`; pastikan
binary client PostgreSQL tersedia. Archive CLI berizin `0600` dan berisi
konfigurasi/secret, database, serta model—perlakukan sebagai data sensitif.

Uji restore berkala di node isolasi:

```bash
sudo systemctl stop sagedral-ml
sudo -u sagedral sagedral-ml backup restore \
  --source /path/backup.tar.gz --confirm
sudo -u sagedral sagedral-ml database migrate
sudo systemctl start sagedral-ml
```

Restore menolak path traversal dan link archive. File lama disalin sebagai
`before-restore` sebelum overwrite.

## Disaster recovery node tunggal

1. Isolasi node gagal dari jalur inline atau pindahkan VIP ke passive.
2. Provision OS/Python 3.8.10 dan install versi aplikasi yang sama.
3. Pulihkan config, database, model, GeoIP DB, serta certificate TLS.
4. Jalankan `config validate` dan `database migrate`.
5. Jalankan tanpa capture, cek `/healthz`, `/readyz`, login, audit, dan model.
6. Aktifkan capture; cek drop dan reconcile DB blocklist ke firewall.
7. Masukkan kembali node ke jalur inline secara bertahap.

## Failover HA

- Keepalived mengecek `sagedral-ml health`.
- Node passive harus memakai PostgreSQL shared/replicated dan shared secret HA
  yang sama, tetapi `node_id` berbeda.
- Saat VIP berpindah, verifikasi route, ARP/NDP, dashboard, capture, dan
  `nft list table inet sagedral`.
- Endpoint peer hanya boleh diakses antar management IP. Rotasi shared secret
  di kedua node dalam maintenance window.

## Upgrade

```bash
sudo systemctl stop sagedral-ml
sudo -u sagedral sagedral-ml backup create \
  --output /var/lib/sagedral-ml/backups/pre-upgrade.tar.gz
python3 -m pip install --upgrade .
sudo -u sagedral sagedral-ml database migrate
sudo -u sagedral sagedral-ml config validate
sudo systemctl start sagedral-ml
sagedral-ml health
```

Lalu jalankan:

```bash
pytest -q
python scripts/pcap_regression.py --self-test
python scripts/benchmark.py --iterations 10000 --minimum-fps 1000
```

Untuk rollback, stop service, install wheel/commit sebelumnya, pulihkan archive
pre-upgrade, jalankan migrasi versi tersebut, lalu start. Jangan downgrade
schema secara destruktif tanpa backup teruji.

## TLS

1. Bind API ke `127.0.0.1`.
2. Pasang certificate/key dengan permission ketat.
3. Install template `deploy/nginx-sagedral.conf` ke konfigurasi Nginx.
4. Ganti hostname dan path certificate.
5. Jalankan `nginx -t`, reload, lalu uji HTTPS dan WebSocket.

## Acceptance production

Sebelum inline:

- seluruh test dan build dashboard hijau;
- replay PCAP organisasi memenuhi precision/recall yang disepakati;
- soak test minimal 24 jam pada traffic representatif;
- packet drop di bawah batas organisasi;
- failover VRRP dan restore backup diuji, bukan hanya dikonfigurasi;
- fallback/synthetic model tidak dianggap sebagai model production;
- secret default sudah dirotasi dan file bootstrap diamankan.
