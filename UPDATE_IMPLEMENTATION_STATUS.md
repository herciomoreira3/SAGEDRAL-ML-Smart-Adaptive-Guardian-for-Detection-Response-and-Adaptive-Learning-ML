# Catatan Implementasi `update.md`

Tanggal audit: 2026-07-26. Runtime kompatibilitas: Python 3.8.10+.

## Fase 1

Seluruh F1-01 sampai F1-22 telah diimplementasikan:

- JWT, admin bootstrap aman, RBAC, login/protected dashboard.
- Config TOML persisten dan daftar restart lengkap.
- Reconcile DB ke firewall, CIDR whitelist, WAL/retention/backup.
- Dependency container, rule JSON/TOML + DSL AST tanpa Python execution.
- Capture stats/watchdog, RunningStat, IPv6, DB rule hot reload/index.
- Rate limit, structured error/log, model init installer, systemd watchdog.
- UI Tetun dan confirmation dialog.
- Test engine/capture/extractor serta CI Python 3.8-3.11.

## Fase 2

F2-01 sampai F2-18 dan F2-20 tersedia:

- Audit UI/API; CEF syslog; Slack/Teams webhook; Telegram/email.
- Strike escalation persisten, adaptive feedback/retrain quality gate,
  atomic model swap, PSI drift, dan GeoIP.
- RBAC tiga role, canonical whitelist CRUD, CSV server-side/filter/pagination.
- WebSocket auth/keepalive/topic/ring buffer.
- Per-rule parameter override, Alembic, multiprocessing ML, batch inference.
- Libpcap backend, Docker Compose, Prometheus/alert rules.
- Replay PCAP generic plus gate precision/recall deterministik di CI.

F2-19 (target coverage 80%) belum memenuhi angka acceptance: suite meningkat
dari 38 menjadi 59 test, seluruhnya lulus, tetapi coverage total aktual adalah
41%. Laporan ini sengaja tidak menyembunyikan modul CLI/orchestrator/adapter
Linux yang belum tercakup penuh.

## Fase 3

F3-01, F3-02, F3-03, F3-05 sampai F3-13 tersedia:

- Keepalived active-passive + authenticated blocklist sync.
- PostgreSQL async backend, Alembic, dan `pg_dump`.
- AF_PACKET TPACKET_V2 `PACKET_RX_RING`, BPF kernel, kernel drop stats.
- Sliding-window connection limiter; block CIDR IPv4/IPv6.
- Rule DSL dan per-rule source whitelist override.
- LRU-style flow cap/eviction.
- Nginx TLS/CSP/HSTS/rate-limit template.
- Permission per aksi dan user CRUD dashboard.
- `py-spy` performance profile artifact di CI.
- Runbook operasi, DR, upgrade, TLS, HA, dan acceptance.

F3-04 memakai jalur minimum yang secara eksplisit diizinkan `update.md`:
service berjalan sebagai user dedicated `sagedral` dengan bounding/ambient
capability `NET_RAW` dan `NET_ADMIN`, `NoNewPrivileges`, serta hardening
filesystem/kernel systemd. Split literal menjadi tiga daemon UDS terpisah
belum diterapkan.

## Validasi yang sudah dijalankan

- Parse seluruh Python dengan grammar Python 3.8: lulus.
- `compileall`: lulus.
- `pytest`: 59 lulus.
- Replay PCAP fixture: precision 1.00, recall 1.00.
- Benchmark lokal: sekitar 16k flow/detik pada fallback test.
- Dashboard Vite production build: lulus pada audit sebelumnya dan dibangun
  ulang setelah perubahan UI.

## Validasi eksternal wajib

Windows workspace tidak dapat membuktikan behavior kernel Linux. Sebelum
production, jalankan di hardware target:

- live `nftables`/`iptables`, AF_PACKET ring, dan capability systemd;
- Docker image pull/build;
- PostgreSQL/pg_dump;
- Nginx certificate, VRRP/Keepalived, failover dan peer sync;
- MaxMind, SMTP, Telegram, SIEM/webhook;
- dataset PCAP organisasi dan load test 1 Gbps.

Tidak ada klaim 1 Gbps universal tanpa hasil soak test hardware tersebut.
