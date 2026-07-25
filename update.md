# SAGEDRAL-ML — Analisis Menyeluruh & Roadmap Pengembangan Enterprise

> **Versi Dokumen:** `1.0.0-analysis`  
> **Dokumen Rujukan:** [prd.md](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/prd.md) · [implementation_plan.md](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/implementation_plan.md)  
> **Target Pembaca:** Junior Network Engineer · Junior Python Developer · AI Agent Autonomous  
> **Tujuan Dokumen:** Acuan pengembangan SAGEDRAL-ML dari versi "MVP working" menjadi **Enterprise Standard** (layak dipakai 50-500 user, production-grade, maintainable).

---

## Daftar Isi

1. [Executive Summary: Kondisi Saat Ini](#1-executive-summary-kondisi-saat-ini)
2. [Scorecard Kesiapan Production per Modul](#2-scorecard-kesiapan-production-per-modul)
3. [Critical Issues: Bug & Vulnerability Harus Diperbaiki SEKARANG](#3-critical-issues-bug--vulnerability-harus-diperbaiki-sekarang)
4. [Modul 1: CAPTURE (Packet Sniffer) — Analisis + Improvement](#4-modul-1-capture-packet-sniffer--analisis--improvement)
5. [Modul 2: FEATURE EXTRACTION (FlowAggregator) — Analisis + Improvement](#5-modul-2-feature-extraction-flowaggregator--analisis--improvement)
6. [Modul 3: DETECTION ENGINE (Signature + ML + Decision) — Analisis + Improvement](#6-modul-3-detection-engine-signature--ml--decision--analisis--improvement)
7. [Modul 4: IPS RESPONSE (Firewall Block) — Analisis + Improvement](#7-modul-4-ips-response-firewall-block--analisis--improvement)
8. [Modul 5: DATABASE (SQLite) — Analisis + Improvement](#8-modul-5-database-sqlite--analisis--improvement)
9. [Modul 6: BACKEND API (FastAPI) — Analisis + Improvement](#9-modul-6-backend-api-fastapi--analisis--improvement)
10. [Modul 7: FRONTEND DASHBOARD (React) — Analisis + Improvement](#10-modul-7-frontend-dashboard-react--analisis--improvement)
11. [Modul 8: CLI & ORCHESTRATOR — Analisis + Improvement](#11-modul-8-cli--orchestrator--analisis--improvement)
12. [Modul 9: SECURITY HARDENING (Zero Trust untuk NIDPS Sendiri)](#12-modul-9-security-hardening-zero-trust-untuk-nidps-sendiri)
13. [Enterprise Features: Fitur Tambahan Standar Industri](#13-enterprise-features-fitur-tambahan-standar-industri)
14. [Performance & Scalability: Dapati Menangani 1Gbps+](#14-performance--scalability-dapati-menangani-1gbps)
15. [Testing & Quality Assurance (QA) Roadmap](#15-testing--quality-assurance-qa-roadmap)
16. [Deployment DevOps: CI/CD, Backup, Monitoring](#16-deployment-devops-cicd-backup-monitoring)
17. [Roadmap Urutan Pengerjaan (Prioritas 3 Fase)](#17-roadmap-urutan-pengerjaan-prioritas-3-fase)
18. [Appendix A: Estimasi Effort per Task per Fase](#18-appendix-a-estimasi-effort-per-task-per-fase)
19. [Appendix B: Code Reference Semua File Analisis](#19-appendix-b-code-reference-semua-file-analisis)

---

## 1. Executive Summary: Kondisi Saat Ini

### 1.1 Status SAGEDRAL-ML v1.0.0

| Dimensi | Status (Skala A-F) | Penjelasan Singkat |
|---|---|---|
| **Fungsi NIDPS Dasar** | 🟢 **B** | ✅ Capture → Feature → Detect → Block pipeline LENGKAP & JALAN. Semua 9 komponen dari PRD sudah implement. 7 signature rules + ML 2-stage + IPS nftables/iptables DAH ADA. |
| **Bug/Stability** | 🟡 **C** | Ada 7 isu critical (Bab 3): config tidak persist ke file, API zero authentication, SQLite WAL off, whitelist subnet/CIDR tidak support, dll. |
| **Performance** | 🟡 **C** | Work OK untuk 100 Mbps / 50 user. Akan saturasi >300 Mbps: Scapy pure-Python + queue.Queue GIL bottleneck (belum ada AF_PACKET raw socket / DPDK). |
| **Security NIDPS Sendiri** | 🔴 **E** | ❌ Zero authentication API/dashboard! Semua endpoint PUBLIC tanpa login. CORS default `["*"]`. Tombol block IP bisa diclick siapapun yang buka URL. **CRITICAL.** |
| **Test Coverage** | 🟡 **C** | 8 file test (config, database, decision, features, IPS, signature, API). Tidak ada test ML Engine, test flow extractor end-to-end, test sniffer. Estimasi coverage: ~35-40%. |
| **Enterprise Readiness** | 🔴 **E** | ❌ Belum ada: RBAC user management, audit log lengkap, backup DB otomatis, SIEM integration (Syslog/Splunk/Elastic), HA failover, rate limiting API, data encryption at rest. |
| **Maintainability Code** | 🟢 **B** | Struktur bagus, separation of concern jelas tiap modul. Type hints lumayan. Docstring ada di tiap class. Tapi: TODO banyak, custom rule engine via lambda belum sandboxed, config update via dashboard tidak sync ke file TOML. |
| **Documentation** | 🟡 **C** | Ada PRD, implementation plan, walkthrough, topologi basic. Belum ada API spec OpenAPI, runbook ops, troubleshooting FAQ, security policy. Dashboard label Tetun sudah sesuai constraint user. |

### 1.2 Rekomendasi High Level

1. **FASE 1 (URGENT / 1-2 Minggu):** Perbaiki 7 Critical Issues terlebih dahulu sebelum deploy production manapun. Khususnya AUTHENTICATION dan CONFIG PERSIST.
2. **FASE 2 (1 Bulan):** Performance optimization + Enterprise basic features (backup, audit, SIEM syslog).
3. **FASE 3 (2-3 Bulan):** Scalability >1Gbps + HA cluster + RBAC advance.

---

## 2. Scorecard Kesiapan Production per Modul

> Penjelasan Rating: **A** = Production Enterprise Grade · **B** = Production Ready SME · **C** = MVP OK / Perlu Improvement · **D** = MVP Buggy · **F** = Belum Ada / Tidak Bisa Dipakai

| # | Modul | File Utama | Rating | Alasan Utama |
|---|---|---|---|---|
| 1 | Capture Sniffer | [sniffer.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/capture/sniffer.py) | **C** | Scapy AsyncSniffer OK tapi performance bottleneck. Belum ada capture stats, packet drops counting, auto recovery jika interface DOWN. |
| 2 | Feature Extraction | [extractor.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/features/extractor.py) · [models.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/features/models.py) | **B** | FlowAggregator thread safe + 28 fitur sesuai PRD. RAM leak potensial jika flow_timeout panjang + trafik besar. |
| 3 | Signature Engine | [signature_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/signature_engine.py) · [default_rules.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/rules/default_rules.py) | **C** | 7 rules OK tapi rule threshold HARDCODED (tidak configurable per rule). Custom rule via DB condition_expr text tidak dievaluasi (hanya tersimpan, SIG-008+ dari DB tidak jalan!). Custom python file via importlib.exec_module TIDAK SANDBOXED = code injection risk. |
| 4 | ML Engine | [ml_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/ml_engine.py) | **C+** | 2-stage pipeline + graceful 3-tier fallback BAGUS! Tapi akurasi fallback model diragukan (synthetic random), tidak ada model drift detection, tidak ada fitur preprocessing pipeline (scaler) tersimpan. |
| 5 | Decision Engine | [decision_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/decision_engine.py) | **B** | Weighted score formula sesuai PRD. Dedup OK. Tapi: threshold HANYA per level global, tidak ada whitelist per-rule (misal: rule SIG-002 tidak trigger jika src IP adalah monitoring server). |
| 6 | IPS Response | [response.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/ips/response.py) | **B** | Whitelist auto-detect gateway & local IP SANGAT BAGUS. nftables + iptables fallback OK. Tapi: tidak support block CIDR /24, tidak support rate limit src IP, tidak ada quarantine duration bertingkat (repeat offender = lebih lama). |
| 7 | Database | [connection.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/connection.py) · [crud.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/crud.py) · [models.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/models.py) | **C** | Model sesuai PRD tapi: SQLite WAL mode OFF → write contention lambat. Tidak ada composite index. Tidak ada DB backup otomatis. Tidak ada DB encryption. Retention cleanup TIDAK PERNAH DIJALANKAN (tidak ada scheduler call cleanup_old_records!). |
| 8 | API Backend | [main.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/main.py) · routers/* | **D** | ❌ **ZERO AUTHENTICATION**! Semua endpoint POST block/unblock/config TANPA login user. CORS `["*"]` default. Tidak ada rate limit. Tidak ada input validation strict. WS manager tidak memiliki disconnect pada ping timeout. Auto-unblock task reference ips_module via getattr router hack (rapuh). |
| 9 | Dashboard Frontend | App.jsx · pages/* | **C** | UI fungsional, 6 halaman sesuai PRD, WebSocket realtime OK. Tapi: tidak ada Login page. Settings page config flat JSON editor jelek. Tidak ada CSV export. Tidak ada confirmation dialog sebelum block IP. Tidak ada loading skeleton. Label sebagian masih CAMPURAN Inggris + Tetun. |
| 10 | CLI & Orchestrator | [cli.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/cli.py) · [main.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/main.py) | **B-** | Start/stop/status/block/config/train/model/selftest command ada. Tapi: Pid file management tidak robust, tidak ada health check HTTP via CLI, `--no-capture` flag harus main.py argument (bukan CLI command start). Main.py orchestrator: capture thread tidak ada reconnection logic jika crash. |
| 11 | Install / Deployment | install.sh · sagedral-ml.service | **C** | Installer OK. Tapi install.sh belum menjalankan `sagedral-ml model init` sesuai constraint project memory. Tidak ada logrotate config. Tidak ada systemd WatchdogSec / Restart=always robust. |

---

## 3. Critical Issues: Bug & Vulnerability Harus Diperbaiki SEKARANG

> ⚠️ **RULE:** Semua item di bab ini WAJIB diperbaiki di **Fase 1** sebelum SAGEDRAL dipakai production manapun, apalagi sebagai gateway inline.

### CRIT-001: ❌ API & Dashboard Tanpa Authentication (Sangat Parah)

**Severity:** 🔴 **CRITICAL / CVE-like**  
**Lokasi:** [main.py#L64-L136](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/main.py#L64-L136) · Semua router file di `sagedral_ml/api/routers/`

**Masalah Detail:**
- Setiap endpoint `/api/v1/alerts`, `/api/v1/blocked-ips` **POST**, `/api/v1/config` **PUT** bisa diakses SIAPUN tanpa credential.
- Artinya: Orang jahat yang tahu `http://ip-sagedral:8000` BISA:
  1. Membuka daftar blocked IPs → tahu struktur jaringan Anda (reconnaissance)
  2. **MENAMBahkan IP block ke gateway sendiri / DNS server** → Denial of Service via API (menghancurkan operasional)
  3. **Menghapus IP block penyerang asli** → bypass NIDPS
  4. Ubah threshold block menjadi `1.0` → mematikan deteksi secara efektif
  5. Dapat mengkustom rule Python → code injection (lihat CRIT-003)

**Perbaikan Step-by-Step (Detail untuk Junior Dev):**

```
Step 1: Tambahkan dependensi di pyproject.toml
  dependencies = [
    ... (yang sudah ada) ...
    "python-jose[cryptography]>=3.3.0",    # JWT token signing
    "passlib[bcrypt]>=1.7.4",              # Hash password user
    "python-multipart>=0.0.6",             # Form login parsing
  ]

Step 2: Buat file baru sagedral_ml/auth/__init__.py + security.py
  a. Class Auth: method hash_password(password) -> bcrypt hash
  b. Method verify_password(plain, hash) -> bool
  c. Method create_access_token(user_id, expires_minutes=60*8) -> JWT string
     - secret_key = di generate saat install, simpan di config [auth] section
     - algorithm = HS256
  d. Dependency FastAPI: async def get_current_user(token) -> User dict
     - Ambil token dari Header "Authorization: Bearer <token>"
     - Decode JWT, jika invalid -> raise HTTPException 401

Step 3: Buat model User + CRUD di database
  Table "users" kolom: id, username (unique), password_hash, role (admin/analyst/viewer), 
                       created_at, last_login, is_active

  Default admin user diinstall otomatis saat init_db() dengan password random
  (dicetak ke console saat install.sh / simpan ke /root/.sagedral-admin-secret chmod 600)

Step 4: Tambah router baru auth.py di api/routers/
  POST /api/v1/auth/login  (body: username, password form-data)
      -> return access_token + token_type="bearer" + user profile

  GET  /api/v1/auth/me  (butuh login) -> return user profile saat ini

Step 5: BUNGKUS SEMUA endpoint yang berbahaya dengan dependency get_current_user
  a. SEMUA POST/PUT/DELETE endpoint: block IP, unblock, config update, rule create
     -> WAJIB login + minimal role "admin" / "analyst"
  b. GET endpoint (list alerts, traffic, config get) -> WAJIB login + minimal role "viewer"
  c. GET /api/v1/status (untuk health check) -> BOLEH tanpa auth, tapi hanya return status/uptime (TIDAK detail)
  d. WebSocket /ws/alerts -> WAJIB kirim token query parameter, validasi saat connect

Step 6: Frontend: Buat LoginPage.jsx
  a. Route /login -> form username + password
  b. Submit call POST /auth/login, simpan token ke localStorage
  c. Buat <ProtectedRoute/> wrapper di App.jsx, redirect ke /login jika token tidak ada
  d. Semua fetch API client.js: tambahkan Header "Authorization: Bearer <token>"
  e. Jika API return 401 -> clear localStorage + redirect /login

Step 7: Update dashboard label ke BAHASA TETUN sesuai hard constraint user!
  "Username" -> "Naran Uzuariu"
  "Password" -> "Password"
  "Login"    -> "Entra"
  "Logout"   -> "Sai"
  "Access Denied" -> "Aksu La Hetan"
```

---

### CRIT-002: Config Update dari Dashboard TIDAK Disimpan ke File TOML (Loss on Restart)

**Severity:** 🔴 **CRITICAL**  
**Lokasi:** [routers/config.py#L18-L42](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/routers/config.py#L18-L42) · [config.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/config.py)

**Masalah Detail:**
```python
# Di routers/config.py baris 33-34:
config.data.clear()
config.data.update(new_data)
# ❌ HANYA update in-memory dict! TIDAK ada tomli_w.dump() write ke file TOML!
```
- Artinya: Semua perubahan lewat Settings page (ubah block threshold, ubah interface, ubah whitelist) **HANYA bertahan sampai service restart**. Setelah reboot → config kembali ke isi file TOML lama. User 100% akan kecewa, ini BUG fatal.
- Plus: requires_restart list HARDCODED hanya 2 item: `["capture.interface", "api.port"]` padahal banyak lagi config yang butuh restart: `capture.bpf_filter`, `ml.anomaly_threshold`, `signature.disabled_rules`, semua feature extraction param.

**Perbaikan Step-by-Step:**

```
Step 1: Di sagedral_ml/config.py, tambahkan method baru di class Config:

  def save(self, path: Optional[str] = None) -> bool:
      """Serialize in-memory config.data back ke file TOML asli."""
      import tomli_w
      target_path = path or self._last_loaded_path
      if not target_path:
          raise RuntimeError("No config path known; cannot save.")
      
      # Convert nested dict TOML-friendly (pastikan semua value primitive)
      config_dict = self._convert_for_toml(self.data)
      
      try:
          # Backup file lama dulu (rollback safety)
          if os.path.exists(target_path):
              shutil.copy(target_path, target_path + ".bak")
          
          with open(target_path, "wb") as f:   # tomli_w butuh binary mode "wb"
              tomli_w.dump(config_dict, f)
          
          # Chown & chmod sama dengan file asli
          return True
      except Exception as e:
          logger.critical(f"Gagal simpan config TOML ke {target_path}: {e}")
          # Rollback dari .bak jika ada
          if os.path.exists(target_path + ".bak"):
              shutil.copy(target_path + ".bak", target_path)
          return False

  Catatan: Simpan self._last_loaded_path setiap kali Config.from_file() dipanggil.

Step 2: Simpan self._last_loaded_path di constructor / from_file

Step 3: Di routers/config.py PUT /api/v1/config:
  a. Setelah validate: config.data.clear() + config.data.update(new_data)
  b. PANGGIL: save_ok = config.save()
  c. Jika save_ok == False -> raise 500 Internal Error "Failed to persist config to disk"
  d. Expand requires_restart list menjadi LENGKAP:
     requires_restart = [
       "capture.interface", "capture.bpf_filter", "capture.promiscuous", 
       "capture.queue_maxsize",
       "feature_extraction.flow_timeout", "feature_extraction.max_packets_per_flow",
       "ml.enabled", "ml.anomaly_threshold", "ml.classifier_threshold", "ml.model_dir",
       "signature.enabled", "signature.disabled_rules", "signature.custom_rules_file",
       "ips.enabled", "ips.preferred_backend",
       "api.host", "api.port", "api.cors_origins",
       "database.path",
       "general.log_level", "general.data_dir",
     ]
     (Check setiap key config yang diupdate, jika ada di atas, masuk ke return value requires_restart)

Step 4: TAMBAHKAN juga ConfigHistoryModel INSERT otomatis di method save()
  Setiap config key yang berubah:
    INSERT INTO config_history (changed_at, changed_by, config_key, old_value, new_value)
  -> Ini sekaligus mengisi audit trail konfigurasi (salah satu enterprise missing feature).
```

---

### CRIT-003: Custom Signature Rule via Python `exec_module` Bisa Code Injection

**Severity:** 🔴 **CRITICAL**  
**Lokasi:** [signature_engine.py#L56-L66](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/signature_engine.py#L56-L66)

**Masalah Detail:**
```python
spec.loader.exec_module(module)   # Baris 61
```
- Parameter `custom_rules_file` memuat sembarang file Python dan **execute code nya di process utama**.
- Jika penyerang bisa upload file .py ke server (misal via upload nanti), atau jika admin memasukkan file mencurigakan, ini = Remote Code Execution 100%.

**Perbaikan Step-by-Step:**
```
Solusi Jangka Pendek (Fase 1 - Aman dulu):
  Step 1: Tambahkan validation di _load_custom_rules:
    a. Hanya izinkan custom_rules_file jika path nya DALAM SATU FOLDER WHITELIST:
       default: /var/lib/sagedral-ml/custom-rules/
       (configurable di signature.custom_rules_dir)
    b. File permission check: hanya boleh readable, TIDAK boleh executable bit
    c. SANDBOX evaluasi rule: GUNAKAN RestrictedPython package atau
       buat AST parser yang HANYA izinkan:
         - lambda body: perbandingan (== != < > <= >=)
         - aritmatika dasar
         - dict access flow.get("key")
         - boolean operator: and/or/not
       TIDAK boleh: import, function call (kecuali .get()), class, open(), subprocess, dll.

Solusi Jangka Menengah (Fase 2):
  Step 2: Buat DOMAIN SPECIFIC LANGUAGE (DSL) sederhana untuk rule,
    contoh condition_expr di database:
       "syn_flag_count > 100 AND ack_flag_count < 10 AND duration < 5"
    Gunakan library py-expression-eval atau buat parser sendiri dengan shunting-yard
    -> TIDAK PERLU exec Python untuk rule!
    -> condition_expr yang tersimpan di SignatureRuleModel BISA langsung dijalankan
       (saat ini condition_expr TIDAK pernah dijalankan sama sekali, HANYA tersimpan! BUG.)
```

---

### CRIT-004: IPS Whitelist Hanya Support Single IP, Tidak Support CIDR Subnet

**Severity:** 🟠 **HIGH**  
**Lokasi:** [ips/response.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/ips/response.py) · `is_whitelisted()` method

**Masalah Detail:**
User pasti ingin whitelist subnet seluruh LAN kantor: `192.168.1.0/24`. Saat ini jika dimasukkan di config.toml whitelist:
```toml
whitelist = ["192.168.1.0/24"]
```
TIDAK BEKERJA! Karena `is_whitelisted` hanya compare string `==` persis IP.

**Perbaikan Step-by-Step:**
```
Step 1: Di ips/response.py, ubah HARDCODED_WHITELIST check dan config whitelist check
  Ganti dari -> if clean_ip in self.whitelist_set:
  Menjadi:
    a. Saat __init__, parse SEMUA entry di whitelist config + HARDCODED_WHITELIST:
       - Jika entry mengandung "/" -> buat object ipaddress.ip_network(entry, strict=False)
       - Jika entry tanpa "/" -> buat object ipaddress.ip_address(entry)
    b. Simpan di dua struktur:
       self.whitelist_single_ips: set[IPv4Address|IPv6Address]
       self.whitelist_subnets:   list[IPv4Network|IPv6Network]

    c. Method is_whitelisted(ip: str) -> bool:
       ip_obj = ipaddress.ip_address(validate_ip(ip))
       if ip_obj in self.whitelist_single_ips: return True
       for net in self.whitelist_subnets:
           if ip_obj in net: return True
       return False

Step 2: Lakukan hal yang SAMA untuk validate block via API dan IPS manual.
  Jika user POST block IP dan IP tersebut ADA DI DALAM subnet whitelist -> reject 403
  (Saat ini hanya cek exact match.)

Step 3: Update di Dashboard BlockedIPs page, kolom Whitelist Form:
  Boleh masukkan CIDR dan kasih contoh placeholder: "192.168.1.0/24 or 10.0.0.1"
```

---

### CRIT-005: SQLite TIDAK Memakai WAL Mode + Retention Cleanup Tidak Pernah Dijalankan

**Severity:** 🟠 **HIGH**  
**Lokasi:** [connection.py#L26-L34](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/connection.py#L26-L34) · [crud.py#L237-L250](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/crud.py#L237-L250) · [main.py lifespan](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/main.py#L52-L61)

**Masalah Detail:**
1. **WAL = OFF:** Default SQLite menggunakan journal_mode DELETE. Setiap write (INSERT alert/block) = lock entire DB + rewrite journal. Pada rate >10 alert/menit, Akan terjadi write contention. Timeout SQLAlchemy "database is locked".
2. **cleanup_old_records TIDAK PERNAH dipanggil!** Function retention ada di crud.py tapi TIDAK ADA satupun scheduler / background task / cron yang memanggilnya. Akibat: DB file akan tumbuh TANPA BATAS sampai harddisk penuh (bisa 100GB+ setelah 1 tahun production).

**Perbaikan Step-by-Step:**
```
Perbaikan A: WAL Mode (Fase 1)
  Step 1: Di connection.py init_engine(), setelah create_async_engine():
      @staticmethod
      async def _set_sqlite_pragmas(dbapi_connection, connection_record):
          cursor = dbapi_connection.cursor()
          cursor.execute("PRAGMA journal_mode=WAL;")        # Write-Ahead Logging = concurrency OK
          cursor.execute("PRAGMA synchronous=NORMAL;")     # Balance speed vs safety
          cursor.execute("PRAGMA foreign_keys=ON;")        # FK integrity
          cursor.execute("PRAGMA cache_size=-65536;")      # 64MB page cache
          cursor.execute("PRAGMA temp_store=MEMORY;")
          cursor.close()
      
      _engine = create_async_engine(
          db_url, echo=False,
          connect_args={"timeout": 30},                    # Timeout 30 detik (default 5 detik cepat lock)
      )
      # Attach pragma callback:
      from sqlalchemy import event
      event.listen(_engine.sync_engine, "connect", _set_sqlite_pragmas)

Perbaikan B: Retention Scheduler (Fase 1)
  Step 1: Di main.py lifespan, BESERTA auto_unblock_background_task, buat TASK KEDUA:

  async def retention_cleanup_background_task():
      """Jalan setiap JAM 1 kali, hapus data lama melebihi retention_days."""
      while True:
          try:
              await asyncio.sleep(3600)    # 1 jam
              async with _db_conn.AsyncSessionLocal() as db:
                  ret_alerts = int(get_config().get("database", "retention_days_alerts", 30))
                  ret_traffic = int(get_config().get("database", "retention_days_traffic", 7))
                  await crud.cleanup_old_records(db, ret_alerts, ret_traffic)
          except asyncio.CancelledError: break
          except Exception as e:
              logger.error(f"Retention cleanup error: {e}")

  Step 2: Buat juga task backup_db_background_task / 24 jam (Bab 8)
```

---

### CRIT-006: Orchestrator Tidak Sync Engine/Module Instance ke API Routers

**Severity:** 🟠 **HIGH**  
**Lokasi:** [main.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/main.py) Orchestrator + [routers/blocked_ips.py#L45-L47](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/routers/blocked_ips.py#L45-L47) · [routers/model.py#L17-L19](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/routers/model.py#L17-L19)

**Masalah Detail:**
```python
# Di routers/blocked_ips.py line 45:
global_ips_module = getattr(router, "ips_module", None)  # Hacky: attach via attribute router

# Di main.py orchestrator:
# TIDAK ADA kode seperti: blocked_ips.router.ips_module = ips_module_instance
```
- Akibat: Saat route POST /api/v1/blocked-ips dijalankan, `ips_module` = None! Maka block IPS level firewall **TIDAK dijalankan**, HANYA block di DB saja. User manual block IP tapi trafik IP itu tetap lewat. Bug fatal!
- Kasus sama: `model_router.router.ml_engine` attach ke mana? Tidak jelas di orchestrator main.py.

**Perbaikan Step-by-Step:**
```
Step 1: Buat DI (Dependency Injection) Container Global di file baru sagedral_ml/core/container.py
  Singletons:
    class AppContainer:
        config: Config
        signature_engine: SignatureEngine
        ml_engine: MLEngine
        decision_engine: DecisionEngine
        ips_module: IPSModule
        aggregator: FlowAggregator
        capture_module: Optional[PacketCapture]

  global_container = AppContainer()

Step 2: Di sagedral_ml/main.py orchestrator start():
  Setelah instantiasi semua module (line 68-95):
    global_container.config = cfg
    global_container.signature_engine = signature_engine
    global_container.ml_engine = ml_engine
    global_container.decision_engine = decision_engine
    global_container.ips_module = ips_module
    global_container.aggregator = aggregator
    global_container.capture_module = capture

Step 3: Ganti semua getattr router hack di API routes dengan import from container:
  Di routers/blocked_ips.py:
    from sagedral_ml.core.container import global_container
    # Ganti line global_ips_module = getattr(router, "ips_module", None)
    # Menjadi: global_ips_module = global_container.ips_module

  Di routers/model.py:
    global_ml_engine = global_container.ml_engine
```

---

### CRIT-007: Auto-Unblock di Main.py Sync DB → Firewall tapi SEBALIKNYA TIDAK

**Severity:** 🟠 **HIGH**  
**Lokasi:** [main.py#L28-L49](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/main.py#L28-L49) · [ips/response.py IPSModule](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/ips/response.py)

**Masalah Detail:**
1. Saat service **BOOT / RESTART**:
   - BlockedIPModel di DB berisi list IP yang "masih active". Tapi nftables/iptables di kernel TIDAK ingat blocklist setelah reboot (tables hilang di reboot tanpa persistence service).
   - Akibatnya: IP hacker yang masih dalam durasi block OTOMATIS TERBUKA kembali setelah reboot!
2. Tidak ada mekanisme `reconcile_on_startup()`: load semua IP active dari DB → apply ke firewall.

**Perbaikan Step-by-Step:**
```
Step 1: Tambah method IPSModule.load_blocklist_from_db(db)
  async def reconcile_from_db(self, db_session):
      """Panggil saat startup. Load semua active blocked IP dari DB lalu apply ke firewall."""
      from sagedral_ml.database import crud
      active_ips = await crud.get_active_blocked_ips(db_session)
      loaded = 0
      for entry in active_ips:
          if not self.is_whitelisted(entry.ip):
              ok = self.block_ip(entry.ip)   # Kirim perintah nft add element
              if ok: loaded += 1
      logger.info(f"Reconcile blocklist: {loaded}/{len(active_ips)} IPs dari DB diterapkan ke firewall.")

Step 2: Di orchestrator main.py, setelah init_db() dipanggil & IPS module dibuat:
  async with AsyncSessionLocal() as db:
      await ips_module.reconcile_from_db(db)

Step 3 (Opsional Fase 2): Juga buat IPSModule.persist_nftables() via `nft list ruleset > file` + restore saat boot, atau pakai systemd nftables.service Load. Tapi reconcile from DB adalah sumber kebenaran (single source of truth), jadi lebih robust.
```

---

## 4. Modul 1: CAPTURE (Packet Sniffer) — Analisis + Improvement

### 4.1 Analisis Mendalam [sniffer.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/capture/sniffer.py)

| Aspek | Nilai Saat Ini | Catatan |
|---|---|---|
| Library Capture | Scapy AsyncSniffer (Pure Python) | OK untuk < 300 Mbps. Diatas itu drop packet banyak. |
| Thread Safety | packet_queue Queue() thread-safe | Bagus, tapi `capture_thread` di main.py tidak ada exception handler & restart otomatis. |
| Interface Auto Detect | `find_default_interface()` bagus | Bekerja untuk Linux biasa, tapi WSL2 bisa salah pilih. |
| Stats Capture | ❌ TIDAK ADA | Tidak tahu: packets_dropped_kernel, packets_captured_total, bytes_total, drops_due_queue_full |
| Promiscuous Mode | `conf.promisc=conf.promisc_off when stop` | Bagus |
| Handle Interface Down | ❌ TIDAK ADA | Jika kabel LAN dicabut saat jalan, Scapy akan stuck, tidak reconnect. |

### 4.2 Improvement Prioritas (Step by Step)

#### IMP-CAP-01: Tambahkan Capture Statistics + Health Check (Fase 1)

```
File: sagedral_ml/capture/sniffer.py
  a. Tambahkan atribut di __init__:
     self.packets_received_total = 0
     self.packets_dropped_queue_full = 0
     self.started_at = None
     self.last_packet_at = None
     self.interface_status = "down"   # up/down/unknown

  b. Di _enqueue_packet:
     try:
         self.packet_queue.put_nowait(packet)
         self.packets_received_total += 1
         self.last_packet_at = time.time()
         self.interface_status = "up"
     except queue.Full:
         self.packets_dropped_queue_full += 1

  c. Tambahkan method get_stats() -> dict:
     return {
         "interface": self.interface_name or "auto",
         "status": self.interface_status,
         "uptime_sec": time.time() - self.started_at if self.started_at else 0,
         "packets_received": self.packets_received_total,
         "packets_dropped_queue_full": self.packets_dropped_queue_full,
         "drop_rate_pct": 100 * (dropped / max(received, 1)),
         "last_packet_seen_sec_ago": time.time() - self.last_packet_at if self.last_packet_at else None,
     }

  d. Tambah endpoint BARU GET /api/v1/capture/stats yang return stats ini.
     Dashboard Overview: tambah 1 StatsCard kecil "Packet Drop Rate" jika >1% berwarna MERAH.
```

#### IMP-CAP-02: Capture Thread Auto Recovery + Watchdog (Fase 1)

```
File: sagedral_ml/main.py (orchestrator)
  di run_capture() thread function:
    a. Bungkus while loop dengan try/except Exception:
       restart_count = 0
       while not stop_event.is_set():
           try:
               capture.start()
               while not stop_event.is_set() and capture.is_running:
                   time.sleep(1)
                   # Watchdog: jika tidak ada packet > 30 detik padahal interface UP -> restart force
                   stats = capture.get_stats()
                   if stats["last_packet_seen_sec_ago"] and stats["last_packet_seen_sec_ago"] > 30:
                       logger.warning("Capture watchdog: tidak ada packet >30s, restart capture thread")
                       capture.stop()
                       break
           except Exception as e:
               restart_count += 1
               logger.error(f"Capture thread crashed (restart #{restart_count}), restart in 5s: {e}")
               time.sleep(5)
```

#### IMP-CAP-03 (Fase 2): Alternative Capture Backend untuk Throughput Tinggi (>300 Mbps)

**Problem:** Scapy berjalan di user-space Python, setiap packet melalui `recvmsg()` syscall + parsing overhead. Untuk >100k pps, CPU >80% dan drop banyak.

```
Solusi (Pilih SALAH SATU, urut prioritas):

OPSI A (MUDAH, direkomendasikan): Libpcap Fast via python-libpcap / pcap-ct ctypes
  - Install: pip install pcap-ct
  - Capture langsung via libpcap C, filter BPF di kernel (sudah ada bpf_filter, tinggal terapkan)
  - Turunkan CPU capture 30-40% dibanding Scapy pure Python.

OPSI B (SEDANG): AF_PACKET RING via python-bcc / dpkt raw
  - Socket PACKET_RX_RING = zero-copy read dari kernel ke user buffer
  - Perlu C extension / ctypes, tapi throughput sampai ~1M pps 1 core.

OPSI C (SULIT, Enterprise >1Gbps): DPDK / PF_RING ZC
  - Bypass kernel network stack seluruhnya.
  - Butuh dedicated NIC + driver DPDK.
  - Baru perlu jika target >5Gbps.

Implementasi:
  1. Di config [capture] tambahkan key backend="scapy" | "libpcap" | "af_packet"
  2. Buat abstract class BasePacketCapture dengan method start/stop/get_stats/enqueue
  3. Implement ScapyPacketCapture (existing), LibpcapPacketCapture, AFPacketCapture
  4. Factory pattern di __init__ sesuai config backend.
```

---

## 5. Modul 2: FEATURE EXTRACTION (FlowAggregator) — Analisis + Improvement

### 5.1 Analisis Mendalam [extractor.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/features/extractor.py) + [models.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/features/models.py)

| Aspek | Nilai Saat Ini | Catatan |
|---|---|---|
| 28 Fitur PRD | ✅ 100% LENGKAP | Sesuai CICIDS2017 schema, kompatibel model LightGBM. |
| Thread Safety Aggregator | ✅ `with self._lock:` pada add_packet + cleanup | Bagus. |
| Forward/Backward Tracking | ✅ fwd_key vs bwd_key matching | Benar, 5-tuple dibalik untuk response. |
| Completion Check | TCP FIN/RST + timeout + max_pkts | Bagus, tapi: UDP flow tanpa FIN/RST HANYA mengandalkan timeout 60 detik (bagus). |
| Memory Usage FlowRecord | ⚠️ Concern | `fwd_packet_lengths: List[int]` & IAT list disimpan SEMUA packet. Jika max 1000 pkt/flow × 100k concurrent flow = RAM >8GB! |
| NP usage per feature | ✅ np.mean / np.std | Benar, tapi np di-hot loop per flow = overhead. |
| IPv6 Support | ❌ BELUM | `if not packet.haslayer(IP): return None` -> IPv6 = layer IPv6 (scapy.inet6), tidak terdeteksi. |

### 5.2 Improvement Prioritas

#### IMP-FEAT-01: Optimasi Memory FlowRecord, Jangan Simpan List Panjang Selamanya (Fase 1)

```
File: sagedral_ml/features/models.py
  Masalah: self.fwd_packet_lengths = list yang append terus sampai 1000 packet. Untuk statistik mean/std, TIDAK PERLU simpan SEMUA nilai! Bisa pakai Welford's online algorithm (running mean, running variance tanpa simpan semua value).

  Step 1: Tambahkan class RunningStat
    @dataclass
    class RunningStat:
        n: int = 0
        mean: float = 0.0
        m2: float = 0.0      # variance accumulator

        def update(self, value):
            self.n += 1
            delta = value - self.mean
            self.mean += delta / self.n
            delta2 = value - self.mean
            self.m2 += delta * delta2

        @property
        def variance(self):
            return self.m2 / max(self.n - 1, 1) if self.n > 1 else 0.0

        @property
        def std(self):
            return math.sqrt(self.variance)

  Step 2: Ganti fwd_packet_lengths, bwd_packet_lengths, fwd_iat_list, bwd_iat_list
          dari List[int] menjadi RunningStat.
          Total bytes dan total packets TETAP integer counter.

  Step 3: Di add_packet() -> update running stat, bukan append list.
          Di to_feature_vector(): ambil dari .mean dan .std RunningStat.

  Step 4: Hapus semua list panjang di field FlowRecord.
  Result: Memory per flow TURUN 90% + GC pressure berkurang drastis.
```

#### IMP-FEAT-02: IPv6 Support (Fase 1)

```
File: extractor.py _extract_packet_info
  Step 1: Import scapy.layers.inet6.IPv6
  Step 2: Ganti block:
      if not packet.haslayer(IP):
          return None
      ip_layer = packet[IP]
  Menjadi:
      is_ipv6 = packet.haslayer(IPv6)
      if packet.haslayer(IP):
          ip_layer = packet[IP]
      elif is_ipv6:
          ip_layer = packet[IPv6]
      else:
          return None
      src_ip = ip_layer.src
      dst_ip = ip_layer.dst
      protocol = int(getattr(ip_layer, "nh", ip_layer.proto)) if is_ipv6 else int(ip_layer.proto)
      header_len = 40 if is_ipv6 else (int(ip_layer.ihl * 4) if hasattr(ip_layer, "ihl") else 20)
  Step 3: Pastikan semua src_ip dst_ip kompatibel IPv6 string panjang, IP column di DB sudah String(45) = cukup (max IPv6 = 39 char).
```

#### IMP-FEAT-03: Active Flow Count Limit + Eviction (Fase 2)

```
Masalah: Saat DDoS 1 Juta SYN paket dengan src IP random = 1 juta flow keys baru di self.active_flows dictionary, RAM penuh = OOM crash.

Step 1: Tambah config key feature_extraction.max_active_flows default 50000.
Step 2: Di FlowAggregator.__init__, simpan max_active_flows.
Step 3: Di awal process_packet(), BEFORE with lock:
   if len(self.active_flows) >= self.max_active_flows:
       # Evict flows tertua berdasarkan last_end_time
       # Hapus 10% tertua -> kirim ke flow_queue
       sorted_keys = sorted(self.active_flows.keys(), key=lambda k: self.active_flows[k].end_time)
       evict_count = int(0.10 * self.max_active_flows)
       for old_key in sorted_keys[:evict_count]:
           old_flow = self.active_flows.pop(old_key)
           try: self.flow_queue.put_nowait(old_flow)
           except queue.Full: pass
   (Lakukan inside _lock context manager tentu saja.)
```

---

## 6. Modul 3: DETECTION ENGINE (Signature + ML + Decision) — Analisis + Improvement

### 6.1 Analisis Mendalam [signature_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/signature_engine.py) · [ml_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/ml_engine.py) · [decision_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/decision_engine.py)

| Aspek | Nilai Saat Ini | Catatan |
|---|---|---|
| Signature Rule 7 default | ✅ SIG-001 s/d SIG-007 lengkap | Bagus, tapi SIG-002 Port Scan terlalu agresif (1 SYN flow tanpa res = scan). Banyak false positive. |
| Threshold per Rule Configurable | ❌ Hardcoded di lambda | Syn Flood threshold `> 100` tidak bisa diubah per user tanpa edit source code. |
| Custom Rule dari DB dijalankan | ❌ TIDAK DIEKSEKUSI | SignatureRuleModel di DB menyimpan `condition_expr` text, tapi signature_engine TIDAK pernah load dari table DB. BUG BESAR. |
| Rule Override per IP/Subnet Whitelist | ❌ Tidak ada | Contoh: monitoring server nmap ke LAN seharusnya TIDAK trigger SIG-002. Tidak bisa define. |
| ML 3-Tier Fallback | ✅ Bagus sekali! | trained pkl → synthetic LightGBM → zero-dep RuleBasedFallback. Sesuai constraint engineering conventions. |
| ML Model Drift Detection | ❌ Tidak ada | Seharusnya jika distribusi fitur baru berbeda 2σ dari training mean, kirim alert "Model drift terdeteksi, perlu retrain." |
| ML Label Feedback (Active Learning) | ❌ Tidak ada | User click "ini FALSE POSITIVE" di dashboard → masuk ke queue training data retrain berikutnya. Core adaptive learning PRD tapi TIDAK implement. |
| Decision Weighted Score | ✅ `0.4*sig + 0.6*ml` | Sesuai PRD. Tapi bobot statis, tidak auto-tuning. |
| Dedup Window per IP | ✅ 300 detik | Bagus, tidak spam alert. |

### 6.2 Improvement Prioritas

#### IMP-DET-01: Custom Rules dari Database WAJIB Dieksekusi (Fase 1)

```
Masalah Saat Ini:
  User create rule via POST /api/v1/rules -> tersimpan di signature_rules DB table.
  Tapi SignatureEngine.__init__ HANYA load: self.rules = list(SIGNATURE_RULES)  (hanya default_rules.py)
  Artinya rules dari DB TIDAK PERNAH di cek! BOHONG ke user.

Solusi Step by Step:
  Step 1: Tambahkan method SignatureEngine.load_rules_from_db(db_session) async
    async def load_rules_from_db(self, db: AsyncSession):
        """Load additional rules from DB signature_rules table, where enabled = 1."""
        from sagedral_ml.database import crud
        db_rules = await crud.get_custom_signature_rules(db)
        added = 0
        for db_rule in db_rules:
            # Parse condition_expr dari string menjadi callable lambda
            # (Gunakan parser DSL nanti, untuk fase ini kita pakai eval DENGAN restricted globals)
            try:
                safe_globals = {"__builtins__": {}}
                compiled = eval(
                    f"lambda flow: {db_rule.condition_expr}",
                    safe_globals,
                    {}
                )
                rule_dict = {
                    "rule_id": db_rule.rule_id,
                    "name": db_rule.name,
                    "description": db_rule.description,
                    "severity": db_rule.severity,
                    "attack_type": db_rule.attack_type,
                    "condition": compiled,
                    "from_db": True,
                }
                self.rules.append(rule_dict)
                added += 1
            except SyntaxError as e:
                logger.error(f"Skip rule {db_rule.rule_id} dari DB: syntax condition_expr invalid: {e}")
        logger.info(f"Loaded {added} custom signature rules dari database.")

  Step 2: Di orchestrator main.py, sebelum start processing thread:
    async with AsyncSessionLocal() as db:
        await signature_engine.load_rules_from_db(db)

  Step 3: Add field `enabled_rules_ids` & flag hot_reload_rules(). Fase 2 bisa dynamic reload rule tanpa restart.
```

#### IMP-DET-02: Jadikan Threshold Signature Rule Configurable per Rule (Fase 1)

```
File: default_rules.py
  Step 1: Ubah struktur rule dari lambda hardcoded menjadi:
    {
        "rule_id": "SIG-001",
        "name": "SYN Flood",
        ...
        "params": {              # BARU
            "min_syn_count": 100,
            "max_ack_count": 10,
            "max_duration": 5.0,
        },
        "condition": lambda flow, params: (
            flow.get("syn_flag_count", 0) > params["min_syn_count"] and
            flow.get("ack_flag_count", 0) < params["max_ack_count"] and
            flow.get("duration", 100) < params["max_duration"]
        ),
    }

  Step 2: Di signature_engine evaluate loop:
      condition = rule.get("condition")
      params = rule.get("params", {})
      # Ambil override dari config [signature_params][rule_id] jika ada
      cfg_params = self.config.get(f"signature_params.{rule_id}", {}) if self.config else {}
      merged_params = {**params, **cfg_params}
      if condition(flow, merged_params):
          matched = True

  Step 3: Expose di Dashboard Settings per-rule threshold editor.
```

#### IMP-DET-03: User Feedback & Active Learning Retrain Loop (Fase 2)

Ini yang membuat SAGEDRAL adaptive (nama SAGEDRAL: Adaptive Learning) - tapi saat ini tidak ada.

```
Step 1: Tambah table baru feedback_labels di database models:
  Table "feedback_labels":
    id, alert_id (FK), label (TRUE_POSITIVE / FALSE_POSITIVE / UNCERTAIN),
    labeled_by_user, labeled_at, notes, training_vector (JSON 28 feature)

Step 2: Tambah 2 tombol di AlertDetailModal.jsx:
   <Button label="✅ Benar (Ini Ancaman)" onClick=markTruePositive />
   <Button label="❌ Salah (Trafik Normal)" onClick=markFalsePositive />
   POST /api/v1/alerts/{alert_id}/feedback body: {label}

Step 3: Setiap malam (jam 2 pagi), jika ada feedback_labels baru >= 20:
   - Combine: original training CSV + vector feedback (fp = class NORMAL, tp = tetap attack classnya)
   - Panggil sagedral-ml train incremental --feedback-only
   - Simpan model baru dengan versi increment: 1.0.1
   - Hot reload ml_engine.load_models() tanpa restart service.
   - Kirim log: "Adaptive retrain complete, new model version 1.0.1 deployed"
```

#### IMP-DET-04: Model Drift Detector (Fase 2)

```
Step 1: Saat model di-training, simpan juga JSON file "model_profile.json" berisi:
   feature_mean: Dict[str, float]  (rata-rata setiap fitur training normal traffic)
   feature_std:  Dict[str, float]  (standard deviasinya)
   saved ke model_dir.

Step 2: Di MLEngine.predict() atau setiap 100 flow:
   Hitung rata-rata fitur 100 flow terakhir di window berjalan.
   Hitung PSI (Population Stability Index) vs profile training.
   Jika PSI > 0.25 -> "Model drift tinggi (PSI={psi}), kirim alert system di dashboard."

Step 3: Dashboard tambah warning banner jika drift terdeteksi.
```

---

## 7. Modul 4: IPS RESPONSE (Firewall Block) — Analisis + Improvement

### 7.1 Analisis Mendalam [response.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/ips/response.py)

| Aspek | Nilai Saat Ini | Catatan |
|---|---|---|
| Backend nftables + iptables fallback | ✅ Bagus | Support modern & legacy kernel. |
| Whitelist auto-detect (localhost + gateway + semua local IPs) | ✅ SANGAT BAGUS | Fitur kritis agar tidak self-block. |
| Validate IP address via ipaddress module | ✅ Bagus, CIDR perlu ditambah CRIT-004 | |
| Repeat Offender Duration Escalation | ❌ Tidak ada | 1x block = 1 jam, 10x block = 1 jam juga. Seharusnya repeat attacker di durasi lebih lama (strike-based). |
| IP Geolocation Check | ❌ Tidak ada | Blokir otomatis negara high-risk? (opsional). Atau setidaknya tampilkan info negara attacker src IP di dashboard alert. |
| Rate Limit per IP | ❌ Tidak ada | Misal: 100 koneksi/menit dari 1 IP ssh tarpit / drop sementara. TIDAK perlu block permanent. |
| Persistence Across Reboot | ❌ Hanya DB, CRIT-007 | Firewall ruleset di kernel tidak persist. Harus reconcile dari DB. |

### 7.2 Improvement Prioritas

#### IMP-IPS-01: Strike-Based Block Duration Escalation (Fase 1)

```
Masalah: Attacker yang sama datang setiap 1 jam block selesai, terus brute force. Tidak ada efek jera.

Tambahkan table "ip_offense_history" di database models:
  ip, last_offense_at, strike_count (int default 0)

Di IPSModule.block_ip dipanggil:
  Step 1: Ambil strike_count dari offense history.
  Step 2: Strike +1. Update.
  Step 3: Duration = DEFAULT × multiplier
    strike 1: ×1    = 3600 (1 jam)
    strike 2: ×4    = 14400 (4 jam)
    strike 3: ×24   = 86400 (1 hari)
    strike 4: ×168  = 604800 (7 hari)
    strike >= 5: 0  = PERMANEN

Step 4: Simpan strike_count table DB, update row.
```

#### IMP-IPS-02: Geolocation Data untuk Alert Detail (Fase 2)

```
Library: pip install geoip2
Database: MaxMind GeoLite2-Country.mmdb (gratis, CC-BY-SA) atau DB-IP.

Step 1: Tambahkan config [geolocation] db_path = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
Step 2: IPSModule / Decision Engine saat buat AlertEvent:
   src_country = geoip.country(src_ip).name if db exist else "Unknown"
   Tambah field src_country di AlertModel + AlertEvent.
Step 3: Dashboard AlertDetailModal tampilkan Bendera negara + nama.
Step 4 (Opsional): Fitur "Blokir SEMUA IP dari negara CN/NK jika ada attack" → configurable whitelist negara.
```

#### IMP-IPS-03: Connection Rate Limiter per Source IP (Fase 2)

```
Implement sebagai tambahan engine baru sebelum signature / ML:
   class RateLimiter:
       # token bucket per src_ip
       tokens: Dict[str, (last_ts, token_count)]
       rules = {
           "per_ip_ssh_conn_minute": 30,  # >30 koneksi ke port 22/menit -> DROP di iptables nf_conntrack
       }

   Di decision: Jika flow rate > config rate limit → action = RATE_LIMIT (block sementara 5 menit, tidak masuk permanent list).
   Gunakan iptables -I INPUT -s <ip> -m recent --set ... --update --seconds 300 --hitcount 30 -j DROP
```

---

## 8. Modul 5: DATABASE (SQLite) — Analisis + Improvement

### 8.1 Analisis Mendalam [connection.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/connection.py) · [models.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/models.py) · [crud.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/crud.py)

| Aspek | Nilai Saat Ini | Catatan |
|---|---|---|
| DB Type | SQLite via aiosqlite async | OK untuk <100 write/detik. Above itu pindah PostgreSQL. |
| Tabel PRD: alerts, blocked_ips, traffic_stats, config_history, signature_rules | ✅ Semua ADA | |
| CRIT-005 WAL OFF + No Retention Scheduler | 🔴 HIGH | Lihat Bab 3. |
| Indexing | ⚠️ Minimum | Hanya per-column Index untuk id, alert_id, src_ip, timestamp. Kurang composite index untuk filter umum. |
| DB Encryption at Rest | ❌ Tidak ada | SQLite bisa pake SQLCipher (pysqlcipher3) jika data alert sensitif. |
| Backup Otomatis | ❌ Tidak ada | Manual copy file .db saja. Tidak ada backup schedule. |
| Migration System | ❌ Tidak ada | Jika nanti tambah kolom baru (src_country, strike_count), harus ALTER TABLE manual. Tidak ada Alembic / auto-migrate. |

### 8.2 Improvement Prioritas

#### IMP-DB-01: Tambahkan Composite Index yang Sering Dipakai (Fase 1)

```
File: sagedral_ml/database/models.py + Alembic migration nanti
  Daftar index YANG PERLU ADA (query crud sering pakai):

  Table alerts:
    1. idx_alerts_timestamp_desc (timestamp DESC)      -> sudah via column index. Ok.
    2. idx_alerts_severity_timestamp (severity, timestamp DESC)  -> filter severity + waktu.
    3. idx_alerts_src_ip_timestamp (src_ip, timestamp DESC)     -> "Tampilkan semua alert dari IP ini".
    4. idx_alerts_attack_type (attack_type, timestamp DESC)

  Table blocked_ips:
    1. idx_blocked_active_is_active (is_active, blocked_at DESC) -> get_active_blocked_ips paling sering.
    2. idx_blocked_expiry (is_active, auto_unblock_at)          -> get_expired_blocked_ips query CEPAT.

  Table traffic_stats:
    1. idx_traffic_ts_desc (timestamp DESC)  -> sudah ada. Ok.

Tambahkan di SQLAlchemy model:
  __table_args__ = (
      Index("idx_alerts_severity_ts", "severity", "timestamp"),
      Index("idx_alerts_src_ts", "src_ip", "timestamp"),
      Index("idx_blocked_active_expiry", "is_active", "auto_unblock_at"),
  )
```

#### IMP-DB-02: Automatic Backup Database (Fase 1)

```
TIDAK boleh kehilangan data alert untuk keperluan audit / forensik.

Step 1: Buat class DatabaseBackupManager (sagedral_ml/database/backup.py)
  Method: run_full_backup()
    1. Dapatkan db path dari config.
    2. Lock sementara SQLite (PRAGMA wal_checkpoint(TRUNCATE)) agar file konsisten.
    3. Copy file sagedral.db ke backup_dir / sagedral-YYYYMMDD-HHMMSS.db
    4. Compress dengan gzip (turun size 80-90%)
    5. Retention backup: simpan 7 harian + 4 mingguan (rota seperti logrotate)
    6. Configurable: [database] backup_dir, backup_interval_hours, backup_retention_days.

Step 2: Task background ke-3 di lifespan auto jalankan setiap interval.

Step 3: Tambah CLI command: sagedral-ml backup create --output /tmp/backup.gz
                    sagedral-ml backup restore --source /tmp/backup.gz
```

#### IMP-DB-03: Database Migration System (Fase 2)

```
Library: Alembic (standard SQLAlchemy migrations)
  Step 1: pip install alembic
  Step 2: Buat folder sagedral_ml/database/migrations/
  Step 3: alembic init, setup env.py target Base metadata.
  Step 4: Setiap kali ubah model SQLAlchemy:
     alembic revision --autogenerate -m "add src_country to alerts"
     -> generate file migration versi, disimpan di package.
  Step 5: Di init_db() sebelum create_all: jalankan alembic upgrade head (auto apply migration).
```

#### IMP-DB-04 (Opsional Enterprise): PostgreSQL Support (Fase 3)

Jika target deployment >50 NIDPS node atau >200 alerts/menit → SQLite menjadi bottleneck. Buat backend DB configurable:
```toml
[database]
backend = "sqlite"    # atau "postgresql+asyncpg"
connection_string = "postgresql+asyncpg://user:pass@dbhost:5432/sagedral"
```
- Semua CRUD sudah SQLAlchemy → hampir NO CODE UBAH, hanya connection string ganti + install asyncpg driver.
- High Availability DB via PostgreSQL streaming replication / Patroni cluster.

---

## 9. Modul 6: BACKEND API (FastAPI) — Analisis + Improvement

### 9.1 Analisis Mendalam [main.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/main.py) · routers/ di api

| Aspek | Nilai Saat Ini | Catatan |
|---|---|---|
| CRIT-001 Zero Auth | 🔴 CRITICAL | Lihat Bab 3. WAJIB JWT Auth. |
| CORS Default | ⚠️ [*] | Terlalu longgar. Production harus default `[]` dan user configure explicit. |
| Rate Limit API | ❌ Tidak ada | Siapapun bisa spam POST /block IP 1000x / detik. Tidak ada protection. |
| Input Validation Strict | ⚠️ Minimal | BlockIPRequest ada schema. Tapi src_ip dst_ip belum Pydantic IPv4/IPv6 strict type. |
| API Endpoint Coverage | ⚠️ CUKUP | CRUD alert read, block/unblock IP, traffic stats, config, model info, rule create. Kurang: alert feedback, alert close, CSV export, delete alert, whitelist CRUD API terpisah. |
| WebSocket Broadcast | ✅ Dasar OK | Tapi tidak ada per-topic broadcast, tidak ada subscribe filtering, tidak ada keep-alive ping/pong auto-disconnect idle client. |
| OpenAPI / Swagger Docs | ✅ Tersedia otomatis FastAPI | /docs & /redoc endpoint tersedia. Bagus. |
| Error Handling Consistent | ❌ Tidak ada | Tidak ada @app.exception_handler global untuk 500, DB error tidak format JSON. |

### 9.2 Improvement Prioritas

#### IMP-API-01: Rate Limiting Semua Endpoint (Fase 1)

```
Library: slowapi (integrasi FastAPI) + Limiter

Step 1: pip install slowapi limits
Step 2: Di main.py create_app:
   from slowapi import Limiter, _rate_limit_exceeded_handler
   from slowapi.util import get_remote_address
   from slowapi.errors import RateLimitExceeded

   limiter = Limiter(key_func=get_remote_address)
   app.state.limiter = limiter
   app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

Step 3: Attach decorator ke endpoint sensitif:
   @router.post("", response_model=ActionResponse)
   @limiter.limit("10/minute")       # max 10 IP block / menit per IP user
   async def manual_block_ip(...): ...

   @router.put("")
   @limiter.limit("5/minute")        # max 5 ubah config / menit
   async def update_system_config(...): ...
```

#### IMP-API-02: Global Exception Handler + Structured Logging (Fase 1)

```python
# Di main.py create_app, sebelum app.include_router:
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception at {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_server_error", "detail": str(exc) if os.getenv("DEBUG") else "See server logs for details"}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=422,
        content={"error": "validation_failed", "detail": exc.errors()}
    )

# Structured logging JSON (untuk aggregation ELK/Grafana Loki):
from pythonjsonlogger import jsonlogger
handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter(
    "%(asctime)s %(levelname)s %(name)s %(message)s %(module)s %(funcName)s %(lineno)d"
)
handler.setFormatter(formatter)
# apply ke root logger
```

#### IMP-API-03: Endpoint yang Kurang (Fill the Gaps) (Fase 1-2)

```
Tambah endpoint baru (sudah punya Pydantic + CRUD tapi tidak ada API):

1. WHITELIST CRUD (saat ini whitelist cuma di config.toml list)
   POST   /api/v1/whitelist        body: {ip, note}      -> tambah + persist ke config
   DELETE /api/v1/whitelist/{ip}                           -> hapus dari config
   GET    /api/v1/whitelist                                 -> daftar semua IP/CIDR whitelist

2. ALERT ACTIONS
   POST   /api/v1/alerts/{alert_id}/feedback   (lihat IMP-DET-03 Active Learning)
   POST   /api/v1/alerts/{alert_id}/close      -> ubah status alert investigated
   GET    /api/v1/alerts/export.csv?filter=... -> Export CSV / JSON alert untuk laporan forensik
   DELETE /api/v1/alerts/{alert_id}            -> Hapus alert palsu dari DB

3. BULK OPERATIONS
   POST /api/v1/blocked-ips/bulk       body: {ips: [...], reason, duration}  -> banyak IP sekaligus
   POST /api/v1/alerts/bulk-delete     body: {alert_ids: [...]}

4. SYSTEM HEALTH (UptimeRobot / monitoring)
   GET /healthz       -> 200 OK jika semua engine jalan + DB OK + capture OK
                         Return json {ok: bool, unhealthy_modules: []}
   GET /readyz        -> 200 jika model loaded + WS ok.
```

#### IMP-API-04: WebSocket Keep-Alive + Per-Topic Subscribe (Fase 2)

```
Masalah Saat Ini:
   1. Semua event di-broadcast ke semua client, tidak ada granular subscribe.
   2. Jika browser minimize 5 menit (TCP idle tapi tidak kirim ping), WS disconnect tanpa diketahui.
   3. Tidak ada message queue = jika user connect setelah event terkirim, dia ketinggalan alert history.

Step 1: Keep-alive ping every 30s:
   Di connect websocket, buat task send ping setiap 30 detik. Jika send gagal → disconnect.

Step 2: Per-topic subscribe via pesan WS subscribe:
   Client kirim JSON: {"action":"subscribe","topic":"alerts:severity:high"}
   Atau "blocked_ips:*", "traffic:*", dll.
   ws_manager.active_subscriptions[client].add("alerts:high")
   Saat broadcast event, cek subscription client dulu sebelum kirim.

Step 3: Event ring buffer (last 1000 events). Saat client baru connect, kirim 20 event terbaru di buffer sebagai catch-up.
```

---

## 10. Modul 7: FRONTEND DASHBOARD (React) — Analisis + Improvement

### 10.1 Analisis Mendalam [Overview.jsx](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/dashboard/src/pages/Overview.jsx) · [Settings.jsx](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/dashboard/src/pages/Settings.jsx)

| Aspek | Nilai Saat Ini | Catatan |
|---|---|---|
| 6 Halaman sesuai PRD | ✅ Overview, Alerts, Blocked, Traffic, Settings, ModelInfo | Sesuai. |
| WebSocket Real-Time | ✅ via useWebSocket hook | Bagus, bisa refresh otomatis new alert. |
| Label Bahasa Tetun | ⚠️ BERCAMPUR | Hard constraint user: SELURUH label UI dalam bahasa Tetun. Saat ini "System Overview", "Attack Type", "Save Changes" dll masih BAHASA INGGRIS! VIOLATION. |
| Login Page (lihat CRIT-001) | ❌ TIDAK ADA | Semua halaman tanpa proteksi. |
| Confirm Dialog Destructive Action | ❌ Tidak ada | Klik "Block IP" → langsung execute tanpa konfirmasi "Anda yakin block IP ini?" → salah klik = user bisa blokir sendiri secara tidak sengaja. |
| Alert CSV Export | ❌ Tidak ada | Implementasi plan.md nyebutkan export, tapi di Alerts.jsx tidak ada tombol. |
| Accessibility / UX | ⚠️ Bagus dasar | Tidak ada loading skeleton, tidak ada error page 404, mobile responsive sebagian. |
| Whitelist CRUD di UI | ❌ Tidak ada | Settings page tidak ada section whitelist. Blocked page whitelist form? TIDAK. |
| Pagination Alert Table | ⚠️ Limit 50 via API | Backend ada pagination (page, limit param), tapi Alerts.jsx UI tidak ada Next Page button. |

### 10.2 Improvement Prioritas

#### IMP-FE-01: 100% Label Dashboard Terjemahkan ke Bahasa TETUN (FASE 1 - HARD CONSTRAINT USER)

User memory context menyatakan: "Seluruh label dan teks dalam sistem (UI/Dashboard) harus menggunakan bahasa Tetun."

```
Buat file sagedral_ml/dashboard/src/i18n/tet.js:
Export object semua label (lebih mudah buat pemula):
  const TET = {
    // Common
    "save_changes": "Rai Mudansa",
    "loading": "Halo...",
    "cancel": "Kansela",
    "confirm": "Konfirma",

    // Sidebar Menu
    "menu_overview": "Visão Jeral",
    "menu_alerts": "Alertas Seguransa",
    "menu_blocked_ips": "IPs Blokeadu",
    "menu_traffic": "Analiza Trafiku",
    "menu_settings": "Konfigurasaun",
    "menu_model_info": "Informasaun Modelo ML",
    "menu_logout": "Sai Sistema",

    // Overview
    "overview_title": "Visão Jeral Sistema",
    "overview_subtitle": "Monitorizasaun Intrusão Rede Tempu Real",
    "stat_system_status": "Estadu Sistema",
    "stat_active": "Proteção Ativu",
    "stat_recent_alerts": "Alertas Resentes",
    "stat_active_blocked": "IPs Ativu Blokeadu",
    "stat_ml_engine": "Motor ML",

    // Alerts
    "alerts_title": "Lista Alertas Seguransa",
    "alerts_time": "Tempo",
    "alerts_src_ip": "IP Origem",
    "alerts_dst_ip": "IP Destinu",
    "alerts_attack_type": "Tipu Atake",
    "alerts_severity": "Severidade",
    "alerts_action": "Asaun",
    "alerts_details": "Detalhes",
    "alerts_export_csv": "Exporta CSV",
    "alerts_bulk_delete": "Hamos Terselecionadu",

    // Blocked IPs
    "blocked_title": "IPs Ne'ebé Blokeadu",
    "blocked_reason": "Razão",
    "blocked_unblock": "Liberta IP",
    "blocked_manual": "Bloke IP Manual",
    "blocked_whitelist_add": "Aumenta ba Lista Branca",
    "blocked_confirm_block_title": "Konfirma Bloke IP?",

    // dll SEMUA string UI...
  };
  export default TET;

Kemudian di App.jsx / setiap component, import TET dan replace semua string hardcoded Inggris.
```

#### IMP-FE-02: Tambah Login Page + ProtectedRoute (Fase 1 - seiring CRIT-001)

```
File baru: sagedral_ml/dashboard/src/pages/Login.jsx
  Form:
    Input Naran Uzuariu (Username) -> type="text" name="username"
    Input Password                  -> type="password" name="password"
    Button "Entra" (Login)
  Submit handler:
    POST /api/v1/auth/login -> jika success:
      localStorage.setItem("sagedral_token", res.access_token)
      localStorage.setItem("sagedral_user", JSON.stringify(res.user))
      navigate("/overview")
    Jika error 401 -> toast error "Naran uzuariu ka password sala."

File baru: sagedral_ml/dashboard/src/components/ProtectedRoute.jsx
  Check: jika tidak ada token di localStorage -> Navigate("/login")
  Wrap semua routes kecuali /login di App.jsx Router.

Logout: Sidebar item "Sai Sistema" -> clear localStorage, navigate("/login")
```

#### IMP-FE-03: ConfirmDialog untuk Semua Destructive Action (Fase 1)

```
Masalah: Klik tombol "Unblock IP" → langsung API call. Salah klik tombol Unblock pada IP attacker = attacker kembali bebas.

Step 1: Buat shared component ConfirmDialog.jsx.
Step 2: Untuk semua destructive action (Block IP, Unblock IP, Delete Alert, Overwrite Config):
   a. Click handler pertama TIDAK call API langsung.
   b. Munculkan ConfirmDialog:
      title: "Konfirma Bloke IP 203.xx.xx.1?"
      body:  "IP ne'e sei bloke durante 1 oras. Ita boot konfirma?"
      confirmBtn: "Sim, Bloke" (warna merah)
      cancelBtn: "Kansela"
   c. HANYA jika user klik SIM -> eksekusi API call.
```

#### IMP-FE-04: Alerts Export CSV + Pagination UI + Filter Panel (Fase 2)

```
a. Alerts.jsx export CSV:
   Tombol "Exporta CSV" di atas tabel.
   fetch GET /api/v1/alerts?limit=10000 → convert ke CSV format:
      timestamp, src_ip, dst_ip, src_port, dst_port, attack_type, severity, final_score, action_taken, signature_matched
   Download blob dengan nama "sagedral-alerts-YYYYMMDD-HHMMSS.csv"

b. Pagination di bawah tabel alert:
   UI: "Mostra página {page} husi total_pages"  |  Anterior | Próximo | Jump to page
   Gunakan query param page dari API.

c. Filter Panel (atas tabel):
   Dropdown Severity: Todos / Baixu / Mediu / Aas / Kritiku
   Input Search IP Src / Dst
   Date Range picker (start_time, end_time epoch)
```

---

## 11. Modul 8: CLI & ORCHESTRATOR — Analisis + Improvement

### 11.1 Analisis Mendalam [cli.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/cli.py) · [main.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/main.py)

| Aspek | Nilai Saat Ini | Catatan |
|---|---|---|
| CLI Commands sesuai implementation plan | ⚠️ SEBAGIAN BESAR ADA | start, stop, status, config, model init, selftest. TAPI: CLI `sagedral-ml train` (retraining command), `sagedral-ml backup create/restore`, `sagedral-ml whitelist add/remove` TIDAK ADA. |
| PID file management | ⚠️ ada tapi fragile | Check pid running via kill(pid,0) tapi tidak cek process name sesuai (bisa bentrok pid lain). |
| Orchestrator graceful shutdown | ✅ Event stop_signal + capture.stop() | Bagus, tapi thread join tidak ada timeout = bisa stuck shutdown forever. |
| Installer constraint: `sagedral-ml model init` di install.sh | ❌ TIDAK ADA (project memory constraint!) | Install.sh WAJIB execute `sagedral-ml model init` agar model fallback digenerate jika belum ada. Bug di installer. |
| Logging Config | ⚠️ Dasar | Tidak ada file rotation, bisa /var/log/sagedral-ml.log jadi 10 GB setelah 1 tahun. |

### 11.2 Improvement Prioritas

#### IMP-CLI-01: Tambah `sagedral-ml model init` di scripts/install.sh (FASE 1 - PROJECT CONSTRAINT)

Project memory rules: "Installer harus menjalankan `sagedral-ml model init` untuk memastikan file model (.pkl) digenerate jika belum ada."

```bash
# scripts/install.sh, sebelum "systemctl enable sagedral-ml":
# ... bagian install pip, copy service, create folder sudah ada ...

echo "[SAGEDRAL] Generating fallback ML models (penting: first boot)..."
cd /opt/sagedral-ml || exit 1
# Running di virtual env:
if [ -f .venv/bin/sagedral-ml ]; then
    sudo .venv/bin/python -m sagedral_ml.cli model init --force  || true
else
    sudo sagedral-ml model init --force || true
fi
echo "[SAGEDRAL] Model initialization done."
```

#### IMP-CLI-02: Tambah CLI Commands yang Kurang (Fase 1-2)

```
1. TRAINING COMMAND (sesuai implementation plan):
   sagedral-ml train --dataset /data/cicids2017-flowdata.csv
   Opsi: --train-test-split 0.2 --save-dir /var/lib/sagedral-ml/models --hot-reload
   Akan jalankan sagedral_ml/scripts/train_model.py pipeline lengkap.

2. BACKUP COMMAND (seiring IMP-DB-02):
   sagedral-ml backup create  [--output /tmp/sagedral-backup.tar.gz]
   sagedral-ml backup restore --source /tmp/sagedral-backup.tar.gz --confirm
   sagedral-ml backup list    (tampilkan history backup tersedia)

3. WHITELIST CLI (selain API & Config):
   sagedral-ml whitelist add 10.0.0.0/8 --note "Rede Interna Kantor"
   sagedral-ml whitelist remove 10.0.0.0/8
   sagedral-ml whitelist list

4. HEALTH CLI:
   sagedral-ml health       -> panggil GET /healthz, return exit code
   Digunakan di systemd HealthCheck.
```

#### IMP-CLI-03: Logrotate Config + systemd Watchdog (Fase 1)

```
File baru: scripts/logrotate.conf (di copy ke /etc/logrotate.d/sagedral-ml saat install)
/var/log/sagedral-ml.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl kill -s SIGHUP sagedral-ml.service 2>/dev/null || true
    endscript
}

File systemd/sagedral-ml.service add robustness:
[Service]
...
Type=notify
WatchdogSec=60                      # Jika 60 detik tidak kirim NOTIFY_WATCHDOG=1 → auto restart
Restart=on-failure
RestartSec=10s
RestartPreventExitStatus=255
TimeoutStartSec=90
TimeoutStopSec=30
# Run CLI health check setiap 10 menit untuk monitoring external
#ExecReload=kill -SIGHUP $MAINPID
Environment=PYTHONUNBUFFERED=1
```

---

## 12. Modul 9: SECURITY HARDENING (Zero Trust untuk NIDPS Sendiri)

> **Konsep Penting:** SAGEDRAL-ML adalah **POLISI KEAMANAN**. Jika polisi nya sendiri bisa di-bobolan, penjahat bebas lewat! Wajib harden.

### 12.1 Daftar Hardening Step-by-Step (Fase 1-2)

#### SEC-01: Kunci Semua Default Password (setelah CRIT-001 Auth)

```
Install admin user pertama dengan RANDOM password, TIDAK hardcoded admin/admin123.
Di init script:
  ADMIN_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
  echo "$ADMIN_PASS" > /root/.sagedral-admin-secret
  chmod 0600 /root/.sagedral-admin-secret
  insert user admin dengan hash password ADMIN_PASS
  Tampilkan di log install:
    "LOGIN PASSWORD default admin tersimpan di /root/.sagedral-admin-secret."
    "USERNAME: admin"
```

#### SEC-02: Session Token Security (JWT)

```
[auth] di config.toml:
access_token_expire_minutes = 480       # 8 jam (bukan permanen)
refresh_token_expire_days   = 7         # Opsional Fase 2: implement refresh token rotation
jwt_algorithm               = "HS256"
jwt_secret_key              = <generate otomatis saat install.sh, JANGAN COMMIT>

Frontend:
  Jangan simpan token di localStorage (rentan XSS). Pindah ke:
  1. HTTPOnly Cookie (lebih aman dari XSS) + SameSite=Lax
  2. Atau minimal localStorage + CSP policy ketat untuk mencegah XSS.
```

#### SEC-03: Content Security Policy (CSP) + HTTPS Dashboard

```
a. DI PRODUCTION WAJIB AKSES DASHBOARD via HTTPS, bukan plain HTTP port 8000.
   Solusi: Deploy nginx reverse proxy DI DEPAN uvicorn.
   Example /etc/nginx/sites-available/sagedral:
     server {
         listen 443 ssl http2;
         server_name sagedral.kantor.local;
         ssl_certificate     /etc/ssl/certs/sagedral.crt;
         ssl_certificate_key /etc/ssl/private/sagedral.key;
         location / {
             proxy_pass http://127.0.0.1:8000;
             proxy_http_version 1.1;
             proxy_set_header Upgrade $http_upgrade;   # penting WebSocket
             proxy_set_header Connection "upgrade";    # penting WebSocket
             proxy_set_header Host $host;
             proxy_set_header X-Real-IP $remote_addr;  # rate limiter via nginx
         }
     }
   Config [api] host = "127.0.0.1" (hanya listen localhost, akses luar via NGINX saja).

b. Tambah CSP header di FastAPI / Nginx:
   Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';
   (Lindungi dari XSS + clickjacking.)
```

#### SEC-04: Non-Root Execution Separation (Fase 2)

```
Masalah: Saat ini capture sniffer + nftables butuh root = seluruh process SAGEDRAL berjalan sebagai root.
Jika ada RCE di API (bug), attacker DAPAT AKSES SELURUH SERVER ROOT.

Solusi: Split jadi 3 process privilege separation:
  1. sagedral-capture (user root: butuh AF_PACKET + CAP_NET_RAW)
     Capture packet, kirim ke Unix Domain Socket ke process utama.
  2. sagedral-ips (user sagedral-fw: CAP_NET_ADMIN saja)
     Hanya handle nftables / iptables command. API via gRPC / UDS.
  3. sagedral-core (user sagedral: unprivileged, TIDAK ADA root)
     Semua feature extraction, detection, API dashboard, database.
     Berjalan sebagai user normal tidak memiliki filesystem akses luas.

Jika ini SULIT untuk junior: minimal jalan process dengan user dedicated `sagedral` bukan root + set capabilities via setcap:
   sudo setcap cap_net_raw,cap_net_admin=ep /path/to/python
   sudo setcap cap_net_raw,cap_net_admin=ep /path/to/sagedral-ml
```

#### SEC-05: Input Output Sanitization Strict

```
a. Semua parameter API (src_ip dst_ip, rule condition_expr, attack_type) di strict type:
   Pydantic model field: IPvAnyAddress untuk IP.
   IpNetwork untuk CIDR.
   field String(50) max length.
b. Sanitize output ke Dashboard:
   Jika user kirim alert notes XSS string "<script>steal cookie</script>",
   selalu HTML escape sebelum render (React secara default sudah escape kecuali __html).
   Jangan gunakan dangerouslySetInnerHTML tanpa sanitize.
```

---

## 13. Enterprise Features: Fitur Tambahan Standar Industri

> Semua item di bab ini TIDAK ADA di v1.0.0. Prioritas implementasi Fase 2 ke atas.

### ENT-01: Audit Log Lengkap (Fase 2)

`ConfigHistoryModel` sebatas untuk konfigurasi. Butuh audit log SEMUA AKSI USER:
- Siapa (user_id) login jam berapa dari IP mana
- Siapa block IP apa, alasan apa
- Siapa ubah threshold
- Siapa unblock IP penting (misal IP attacker diunblock tanpa alasan = perlu investigasi internal)

```
Buat table "audit_logs" di DB models:
  id, timestamp, user_id, username, action_type, target_entity, target_id, ip_address, user_agent, detail_json

Di setiap endpoint POST/PUT/DELETE:
  Setelah action sukses, INSERT audit log:
  INSERT INTO audit_logs (..., action_type="BLOCK_IP", target_entity="ip", target_id=clean_ip, detail_json={"reason": reason, "duration": dur})

Tambah halaman dashboard baru: "Auditoria" -> Admin bisa filter: who did what when from where.
```

### ENT-02: SIEM Integration via Syslog / Webhook (Fase 2)

NIDPS enterprise WAJIB bisa kirim alert ke sistem yang lebih besar (Splunk, Elastic, Wazuh, FortiSIEM).

```
a. Syslog Outbound:
   [siem] di config.toml
   enabled = true
   syslog_server = "10.0.0.50"
   syslog_port = 514
   syslog_format = "CEF"  (Common Event Format standard SIEM)
   Minimal severity = MEDIUM (LOW tidak dikirim, hemat bandwidth)

   Setiap alert baru:
     kirim UDP syslog message CEF:0:SAGEDRAL:ML-NIDPS:1.0:1001:{attack_type}:{severity}|... dll
     Library: pip install syslog-rfc5424-logging-handler

b. Webhook Outbound (Slack / Discord / Teams / Custom):
   [siem.webhooks]
   slack = "https://hooks.slack.com/services/T00/B00/XXXX"
   teams = "https://outlook.office.com/webhook/..."
   Setiap alert baru → POST JSON ke URL webhook. Opsional filter severity HIGH/CRITICAL.
```

### ENT-03: Multi-User RBAC (Role-Based Access Control) (Fase 2)

```
3 Role minimum enterprise:
  Role 1: VIEWER (readonly):
    - Boleh: lihat semua halaman dashboard, download report CSV, filter alert
    - DILARANG: block/unblock IP, ubah config, apapun yang menulis state.
  Role 2: ANALYST:
    - Semua VIEWER + block/unblock IP, close alert, kasih feedback true/false positive.
    - DILARANG: ubah signature threshold, ubah interface capture, ubah whitelist subnet.
  Role 3: ADMIN (superuser):
    - SEMUA akses: user management, config ubah, delete rule, system restore, whitelist global.

Implementasi:
  Table users + kolom role (string: 'viewer'|'analyst'|'admin').
  Dependency FastAPI baru: require_role(role_name), wrap endpoint sensitif.
  Dashboard Settings page: HANYA ADMIN yang bisa buka.
  Frontend: Berdasarkan user.role dari localStorage → hide/show menu Settings.
```

### ENT-04: Scheduled & Email / Telegram Notification (Fase 2)

```
Notification = Alert jika ada ancaman kritikal, tidak perlu user buka dashboard 24/7.

[notification]
telegram_bot_token = "74xxxx:AAxxxx..."
telegram_chat_id = -1001234567890
email_smtp_host = "smtp.gmail.com"
email_smtp_port = 587
email_sender = "sagedral@kantor.local"
email_recipients = ["soc-team@kantor.local", "admin@kantor.local"]
notify_on_severity = "HIGH"   # Hanya HIGH dan CRITICAL yang notifikasi

Implementasi: NotifierManager class yang subscribe AlertEvent, kirim via Telegram API / SMTP.
Pesan Telegram:
  🚨 [ALERT KRITIK] SAGEDRAL-ML @ sagedral.kantor.local
  🕐 Waktu: 2026-07-25 15:45:03
  🌍 Src IP: 185.xx.xx.xx (🇷🇺 Russia)
  🎯 Target: 203.xx.xx.xx:22 (SSH)
  ⚔️ Tipu: BruteForce SSH (SIG-005 matched)
  📊 Skor: 92%
  🚨 Asaun: IP otomatis diblok selama 1 jam.
```

### ENT-05: High Availability (HA) Cluster (Fase 3)

Untuk enterprise, tidak boleh single point of failure.

```
Topologi HA Active-Passive:
  [SAGEDRAL NODE 1 (ACTIVE)] -- [Keepalived VRRP 192.168.1.1]
  [SAGEDRAL NODE 2 (PASSIVE)]

Requirement:
  1. Keepalived mengelola Virtual IP bersama 192.168.1.1 = gateway LAN.
  2. PostgreSQL backend shared / replicated.
  3. Blocklist sync via REST API antar node.
  4. Jika Node 1 mati → Keepalived 3 detik failover VIP ke Node 2.
  5. Node 2 reconcile blocklist ke nftables dalam <10 detik.
```

---

## 14. Performance & Scalability: Dapati Menangani 1Gbps+

### 14.1 Benchmark Target per User Scale

| Scale | Users | Bandwidth | Target pps | SAGEDRAL Minimum Specs | Yang Perlu Di-Upgrade |
|---|---|---|---|---|---|
| Home / Lab | <10 | 50 Mbps | 5k pps | Core i3, 4GB, SSD 10GB | Default v1.0.0 OK, tidak perlu apa-apa. |
| **SME Production** | 50-200 | 300 Mbps | 50k pps | Core i5 4C, 8GB | IMP-CAP-01 Stats, IMP-DB-01 WAL, IMP-FEAT-01 Memory Optim. |
| Enterprise Mid | 200-1000 | 1 Gbps | 200k pps | Xeon E-2200 8C, 16GB, 50GB NVMe | IMP-CAP-03 libpcap/AF_PACKET capture, IMP-DB-04 PostgreSQL, Rate Limiter. |
| Enterprise Large | >1000 | 10 Gbps | 1.5M pps | 2× Xeon Silver, 64GB, NIC dual-port | DPDK capture, Cluster multi-node, Suricata integration opsional. |

### 14.2 Performance Improvement Step (Fase 2)

#### PERF-01: Multi-Processing Detection Pipeline (Bypass GIL)

```
Masalah: Python GIL = 1 process hanya bisa pakai 1 CPU core. 100k pkt/sec = bottleneck 1 core penuh.
Solusi: Pisahkan detection signature + ML ke ProcessPoolExecutor (multiprocessing) bukan thread.
  - Orchestrator: Capture Thread (1 core) + Feature Thread (1 core)
  - Queue flow_record ke ProcessPoolExecutor(max_workers = CPU_COUNT-2)
  - Tiap worker: SignatureEngine.evaluate + MLEngine.predict (mengolah 1 flow)
  - Hasil kembalikan ke thread utama -> DecisionEngine + IPS.

Dapat scaling linear dengan jumlah core. Core i5 4 core: throughput detection ~x2.5 lipat.
```

#### PERF-02: Batching Inference ML

```
Masalah: Setiap 1 flow → MLEngine.predict 1 row LightGBM. Overhead per-call besar.
Solusi: Buffer 32 flow terakhir, inference dalam 1 batch predict 32 row.
  Tambah micro-batch queue: kumpulkan flow ke batch.
  Jika timeout 50ms ATAU batch size mencapai 32 → kirim 1 kali model.predict().
  Dapat speedup 5-10x inference karena LightGBM optimal di batch.
```

#### PERF-03: Profile Hot Loop dengan Profiler

```
Action item untuk setiap release:
  Run dengan py-spy / pyinstrument saat traffic replay CICIDS dataset.
  $ py-spy top -- python sagedral_ml/main.py
  Identify 5 fungsi TERLAMA / terhot.
  Optimize:
    1. Cythonize jika pure math loop.
    2. Ganti dict access ke class __slots__ jika object banyak.
    3. Ganti f-string log ke logger %s format agar tidak format string jika level tidak aktif.
```

---

## 15. Testing & Quality Assurance (QA) Roadmap

### 15.1 Kondisi Saat Ini: Test Coverage Analisis

```bash
# (Simulasi pytest --cov=sagedral_ml tests/ - tidak ada report actual, estimasi berdasarkan file test)

Tests tersedia:
  tests/test_config.py         -> OK config parsing
  tests/test_database.py       -> OK basic CRUD model
  tests/test_decision_engine.py-> score formula
  tests/test_feature_models.py -> FlowRecord feature vector match 28 dimensi
  tests/test_ips.py            -> whitelist / validate IP
  tests/test_signature_engine.py -> 7 default rules on mock flows
  tests/test_api.py            -> status, alerts endpoint, block whitelist
  tests/test_ml_engine.py      -> ❌ TIDAK ADA
  tests/test_extractor.py      -> ❌ TIDAK ADA (FlowAggregator end2end)
  tests/test_capture.py        -> ❌ TIDAK ADA (butuh PCAP replay test)
  tests/test_main.py           -> ❌ TIDAK ADA (orchestrator lifecycle)

ESTIMASI COVERAGE: ~38-42% line coverage.
TARGET FASE 1: >60%, TARGET FASE 2: >80%.
```

### 15.2 QA Improvement Step by Step

#### QA-01: Tambah Test Engine yang Kurang (Fase 1)

```
File baru: tests/test_ml_engine.py
  Fixture: mock feature vector.
  Test 1: Predict dengan fallback rule-based (mock environment tanpa lightgbm)
  Test 2: anomaly_score return di range [0.0, 1.0]
  Test 3: Jika anomaly_threshold tinggi (0.99) → is_anomaly = False
  Test 4: RuleBasedFallback vs MOCK_SYN_FLOOD_FLOW → attack_class harus DDoS
  Test 5: load_models success version berakhiran -fallback / -rulebased.

File baru: tests/test_extractor.py
  Test 1: Inject 3 packet TCP 3-way-handshake (SYN, SYN-ACK, ACK), 
          verify flow terbentuk dengan 3 total_packets, 1 syn_flag_count, 1 ack.
  Test 2: Inject FIN/RST flag → flow auto-complete langsung ke queue.
  Test 3: timeout cleanup 65 detik → flow tanpa flag masuk ke queue via cleanup_timeouts.

File baru: tests/test_capture.py (menggunakan PCAP sample):
  Simpan file fixtures/sample-http.pcap, lalu mock capture sniffer dengan replay pcap via dpkt.
  Verify packet_queue menerima packet jumlah sesuai.
```

#### QA-02: CI/CD Pipeline GitHub Actions (Fase 1)

```
File baru: .github/workflows/ci.yml
  Triggers: push main, pull_request ke main.
  Jobs:
    1. lint:
        python 3.10, pip install ruff, run: ruff check sagedral_ml --fixable=I
        ruff format --check (code style check)
    2. test:
        strategy matrix: python 3.8 / 3.9 / 3.10 / 3.11 ubuntu 22.04
        steps:
          - checkout
          - sudo apt-get install libpcap-dev nftables
          - pip install -e .[dev]
          - pytest tests/ -v --cov=sagedral_ml --cov-report=xml
          - Upload coverage ke codecov / artifact
    3. build-frontend:
        node 18, cd sagedral_ml/dashboard, npm install, npm run build
        verify folder static/ terisi (dashboard berhasil bundle)
    4. security-scan:
        pip install safety bandit
        safety check   -> scan vulnerable dependencies
        bandit -r sagedral_ml -lll   -> scan security anti-pattern source (exec, yaml.load unsafe)
```

#### QA-03: Replay PCAP Dataset CI End to End (Fase 2)

```
Dataset: CICIDS2017 sample PCAP (public 100MB).
Test e2e:
  1. Start orchestrator dengan capture mode PCAP replay (bukan live interface).
  2. Replay 10 menit trafik CICIDS yang sudah ada label ground truth.
  3. Setelah selesai, hitung:
     - Precision: % alert yang benar adalah attack (ground truth)
     - Recall: % attack ground truth yang terdeteksi alert
  4. FAIL CI jika Recall < 85% ATAU Precision < 70%.
  Ini mencegah developer update code yang malah bikin deteksi menurun.
```

---

## 16. Deployment DevOps: CI/CD, Backup, Monitoring

### 16.1 Production Monitoring Stack untuk SAGEDRAL

SAGEDRAL memantau jaringan, tapi SIAPA yang memantau SAGEDRAL JIKA DIA MATI?

```
Monitoring Prometheus + Grafana (standard enterprise):
  Step 1: Tambah library prometheus-fastapi-instrumentator ke FastAPI app.
  Step 2: Expose metrics GET /metrics endpoint:
    Metrik kritis:
      - sagedral_alerts_total{severity,attack_type}  counter
      - sagedral_blocked_ips_active gauge
      - sagedral_capture_packets_total counter
      - sagedral_capture_drops_total counter        # ALERTING jika >1% selama 5 menit
      - sagedral_db_query_duration_seconds histogram
      - sagedral_ml_prediction_duration_ms histogram
      - process_cpu_percent gauge, process_memory_rss_bytes gauge (via psutil)
  Step 3: Prometheus scrape endpoint tiap 15 detik.
  Step 4: Grafana dashboard 1 panel khusus "SAGEDRAL Health" (Ops team pakai ini).
  Step 5: Alertmanager rule:
    - Jika sagedral down (up == 0) → Telegram / email SOC on-call.
    - Jika drop rate >2% → "NIDPS packet drop tinggi, bottleneck!".
    - Jika db file size > 50GB → "DB hampir penuh, retention atau backup perlu!".
```

### 16.2 Containerized Docker Deployment (Fase 2)

Memudahkan Juniors deploy tanpa setup OS panjang.

```
Dockerfile multi-stage:
  Stage 1 (builder-dashboard): node:18, npm install, npm run build -> output static.
  Stage 2 (builder-python): python:3.11-slim, pip install . -> /install
  Stage 3 (runtime image): python:3.11-slim-bookworm
    apt-get install libpcap-dev nftables iptables iproute2 procps
    Copy site-packages dari builder-python.
    Copy static folder dari builder-dashboard ke sagedral_ml/static.
    Entrypoint: ["tini", "--", "sagedral-ml", "start", "--no-daemon"]
    EXPOSE 8000
    HEALTHCHECK CMD sagedral-ml health || exit 1

docker-compose.yml 1 command deploy lengkap:
  services:
    sagedral:
      image: sagedral-ml:latest
      network_mode: host        # butuh akses semua interface capture
      cap_add: [NET_ADMIN, NET_RAW]
      volumes:
        - ./config.toml:/etc/sagedral/config.toml:ro
        - sagedral_data:/var/lib/sagedral-ml
        - ./logs:/var/log
      restart: unless-stopped
    node_exporter:   # opsional monitoring host
    grafana:
    prometheus:
```

---

## 17. Roadmap Urutan Pengerjaan (Prioritas 3 Fase)

### FASE 1: Critical Bug Fix + Production Ready Basic (Estimasi: 1-2 Minggu)

> **Definition of Done Fase 1:** Boleh dipakai inline sebagai Gateway SME (50 user) tanpa risk "sistemnya sendiri diserang / data hilang".

| ID | Tugas | Dokumen Referensi | Prioritas | Est Effort (orang-jam) |
|---|---|---|---|---|
| F1-01 | 🔐 Implementasi JWT Authentication + User Management (Admin default) | CRIT-001 · IMP-FE-02 | 🔴 MUST | 16 |
| F1-02 | 💾 Config Update Persist ke TOML + Expand requires_restart | CRIT-002 | 🔴 MUST | 8 |
| F1-03 | 📛 Reconcile Block List DB → Firewall saat Startup | CRIT-007 | 🔴 MUST | 6 |
| F1-04 | 🛡️ CIDR Subnet Whitelist Support | CRIT-004 | 🔴 MUST | 4 |
| F1-05 | 💽 SQLite WAL Mode + Retention Cleanup Scheduler (1 jam) | CRIT-005 | 🔴 MUST | 6 |
| F1-06 | 🧩 App Container (Dependency Injection) + Attach Engine ke Router (IPS Module None bug) | CRIT-006 | 🔴 MUST | 8 |
| F1-07 | 🏗️ Sandboxing Custom Rule Loader (basic path whitelist) | CRIT-003 | 🟠 SHOULD | 6 |
| F1-08 | 📊 Capture Stats Endpoint + Dashboard Packet Drop Rate | IMP-CAP-01 | 🟠 SHOULD | 6 |
| F1-09 | 🚦 Watchdog Capture Thread Auto Recovery | IMP-CAP-02 | 🟠 SHOULD | 6 |
| F1-10 | ⚡ FlowRecord Memory Optim (RunningStat, hapus list panjang) | IMP-FEAT-01 | 🟠 SHOULD | 8 |
| F1-11 | 🌐 IPv6 Support di Feature Extractor | IMP-FEAT-02 | 🟠 SHOULD | 4 |
| F1-12 | 🎛️ Custom DB Rules Dieksekusi (tidak hanya tersimpan) | IMP-DET-01 | 🔴 MUST | 8 |
| F1-13 | 💾 DB Composite Indexes | IMP-DB-01 | 🟠 SHOULD | 2 |
| F1-14 | 💾 DB Scheduled Backup + CLI Backup Command | IMP-DB-02 | 🔴 MUST | 8 |
| F1-15 | 🛑 API Rate Limiting (slowapi) | IMP-API-01 | 🟠 SHOULD | 4 |
| F1-16 | ⚠️ Global Exception Handler + Structured JSON Logging | IMP-API-02 | 🟠 SHOULD | 4 |
| F1-17 | ✅ Installer Jalankan `sagedral-ml model init` | IMP-CLI-01 | 🔴 MUST (constraint) | 2 |
| F1-18 | 🔄 Logrotate + systemd watchdog + Restart robust | IMP-CLI-03 | 🟠 SHOULD | 4 |
| F1-19 | 🇹🇱 100% Label UI Tetun (termasuk Login page) | IMP-FE-01 | 🔴 MUST (constraint) | 12 |
| F1-20 | 🔔 ConfirmDialog Semua Destructive Action | IMP-FE-03 | 🟠 SHOULD | 6 |
| F1-21 | ✅ Tambah test_ml_engine + test_extractor + test_capture basic | QA-01 | 🟠 SHOULD | 12 |
| F1-22 | ⚙️ CI GitHub Actions (lint + test + build) | QA-02 | 🟠 SHOULD | 8 |
| | **Total Fase 1:** | | | **~146 orang-jam (~3.5 orang-minggu)** |

---

### FASE 2: Enterprise Basic + Performance (Estimasi: 4-6 Minggu)

> **Definition of Done Fase 2:** SAGEDRAL siap enterprise menengah (100-500 user). Audit trail, SIEM, notifikasi, monitoring lengkap, performance 300Mbps aman tanpa drop.

| ID | Tugas | Prioritas | Effort |
|---|---|---|---|
| F2-01 | 🧾 Audit Log Lengkap + Halaman Dashboard Audit | ENT-01 | 🔴 MUST | 12 |
| F2-02 | 🤝 SIEM Syslog CEF + Slack / Teams Webhook | ENT-02 | 🔴 MUST | 12 |
| F2-03 | 💬 Telegram / Email Notifikasi HIGH / CRITICAL Alert | ENT-04 | 🔴 MUST | 8 |
| F2-04 | 🛡️ Strike-Based Block Duration Escalation | IMP-IPS-01 | 🟠 SHOULD | 6 |
| F2-05 | 🧠 Active Learning Feedback Loop + Retrain Scheduler | IMP-DET-03 | 🟠 SHOULD | 16 |
| F2-06 | 📈 Model Drift Detection PSI Monitoring | IMP-DET-04 | 🟡 COULD | 8 |
| F2-07 | 🌍 IP Geolocation (MaxMind) display negara di alert | IMP-IPS-02 | 🟡 COULD | 6 |
| F2-08 | 👥 RBAC 3 Role (Viewer / Analyst / Admin) | ENT-03 | 🔴 MUST | 18 |
| F2-09 | ➰ Whitelist CRUD API + UI Section Whitelist terpisah | IMP-API-03 + IMP-FE-04 | 🟠 SHOULD | 8 |
| F2-10 | 📥 Alert CSV Export + Pagination + Filter Panel UI | IMP-FE-04 | 🟠 SHOULD | 10 |
| F2-11 | 🧪 WebSocket Keep-Alive + Per-Topic Subscribe + Event Buffer | IMP-API-04 | 🟡 COULD | 8 |
| F2-12 | ♻️ Per-Rule Threshold Configurable | IMP-DET-02 | 🟠 SHOULD | 8 |
| F2-13 | 🗄️ Alembic Database Migration System | IMP-DB-03 | 🔴 MUST | 8 |
| F2-14 | ⚡ MultiProcessing Detection Pool (bypass GIL) | PERF-01 | 🟠 SHOULD | 12 |
| F2-15 | 🏎️ ML Batch Inference Micro-Batch 32 | PERF-02 | 🟠 SHOULD | 8 |
| F2-16 | 🧑‍💼 Capture Backend Alternative libpcap (opsional config) | IMP-CAP-03 Opsi A | 🟡 COULD | 10 |
| F2-17 | 📦 Dockerfile + Docker Compose Production Ready | 16.2 | 🟠 SHOULD | 10 |
| F2-18 | 📈 Prometheus Metrics / Grafana SAGEDRAL Health Dashboard | 16.1 | 🟠 SHOULD | 14 |
| F2-19 | 🏥 Test Coverage Cap → 80% | QA + new | 🟠 SHOULD | 16 |
| F2-20 | 🔎 PCAP Replay E2E Test dengan CICIDS ground truth precision recall check | QA-03 | 🟡 COULD | 12 |
| | **Total Fase 2:** | | **~210 orang-jam (~5 orang-minggu)** |

---

### FASE 3: Enterprise Scale + HA + 1Gbps+ (Estimasi: 6-10 Minggu)

> **Definition of Done Fase 3:** Enterprise High Availability cluster, men-support 1Gbps tanpa drop, security zero-trust architecture, PostgreSQL backend scalable.

| ID | Tugas | Prioritas | Effort |
|---|---|---|---|
| F3-01 | ⚖️ HA Active-Passive via Keepalived + Sync Blocklist | ENT-05 | 🟠 SHOULD | 20 |
| F3-02 | 🗄️ PostgreSQL Backend Support (ganti DB driver configurable) | IMP-DB-04 | 🟠 SHOULD | 12 |
| F3-03 | 🚀 AF_PACKET RING Capture Backend (100k → 1M pps) | IMP-CAP-03 Opsi B | 🟡 COULD | 18 |
| F3-04 | 🔐 Privilege Separation 3 Process (non-root core) | SEC-04 | 🟡 COULD | 20 |
| F3-05 | 🔄 Connection Rate Limiter per Source IP (nf_conntrack recent) | IMP-IPS-03 | 🟡 COULD | 8 |
| F3-06 | 🧑‍💼 DSL Domain-Specific Language rule (not Python exec) | CRIT-03 jangka panjang | 🟡 COULD | 16 |
| F3-07 | 🚧 Flow Aggregator Max Active Flow Limit + LRU Eviction | IMP-FEAT-03 | 🟠 SHOULD | 6 |
| F3-08 | ⚖️ IPS support block CIDR /24 bulk (banned subnet negara) | IMP-IPS extend | 🟡 COULD | 6 |
| F3-09 | 🏷️ Signature Rule Whitelist Override per IP (monitoring server nmap tidak masuk SIG-002) | IMP-DET extend | 🟡 COULD | 8 |
| F3-10 | 🛡️ Full TLS + Nginx reverse proxy + CSP headers (production deployment guide) | SEC-03 | 🔴 MUST | 10 |
| F3-11 | 📜 RBAC Fine-Grained Permission (per-menu / per-action), User Management CRUD UI | ENT-03 advance | 🟡 COULD | 20 |
| F3-12 | 🧪 Performance Regression Suite: CI profile py-spy setiap PR ke main. | QA advance | 🟡 COULD | 12 |
| F3-13 | 📖 Documentation runbook lengkap (Tetun/Indonesia): Operasi harian, Disaster Recovery Procedure, Upgrade Procedure. | Docs | 🟠 SHOULD | 24 |
| | **Total Fase 3:** | | **~180 orang-jam (~4.5 orang-minggu)** |

---

## 18. Appendix A: Estimasi Effort per Task per Fase

### Total 3 Fase (MVP → Enterprise Scale):
```
Fase 1 Critical Basic  : 146 jam   (3.5 minggu, 1 dev / 40 hr/minggu)
Fase 2 Enterprise Mid  : 210 jam   (5 minggu)
Fase 3 Scale HA 1Gbps  : 180 jam   (4.5 minggu)
──────────────────────────────── +
TOTAL                  : ~536 orang-jam = ~13-14 orang-minggu = ~3.25 orang-bulan

Jika 2 junior dev parallel: 6-7 minggu total.
Jika AI agent assist 50% automated: 3-4 minggu total.
```

---

## 19. Appendix B: Code Reference Semua File Analisis

### Core Package Files

| File | Purpose | Link |
|---|---|---|
| [__init__.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/__init__.py) | Package version + WSL Scapy patch | [L9-L47](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/__init__.py#L9-L47) |
| [cli.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/cli.py) | Click CLI entrypoint | [L1-L600+](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/cli.py) |
| [config.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/config.py) | TOML config loader singleton | [L1-L350+](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/config.py) |
| [main.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/main.py) | Orchestrator lifecycle 2 thread + FastAPI | [L1-L250+](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/main.py) |

### Capture Module
| [sniffer.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/capture/sniffer.py) | Scapy AsyncSniffer capture → packet_queue |
---

### Feature Module
| [extractor.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/features/extractor.py) | FlowAggregator packet→flow | [L18-L157](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/features/extractor.py#L18-L157) |
| [models.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/features/models.py) | FlowRecord dataclass + to_feature_vector (28 fitur) | [L12-L138](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/features/models.py#L12-L138) |

### Detection Module
| [signature_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/signature_engine.py) | Rule evaluator + custom rule loader (unsafe exec) | [L40-L104](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/signature_engine.py#L40-L104) |
| [default_rules.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/rules/default_rules.py) | 7 default signature rules (threshold hardcoded) | [L7-L89](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/rules/default_rules.py#L7-L89) |
| [ml_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/ml_engine.py) | MLEngine 2-stage + 3-tier fallback (trained → synthetic → rulebased) | [L161-L398](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/ml_engine.py#L161-L398) |
| [decision_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/decision_engine.py) | Weighted final_score + dedup + severity override | [L36-L120](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/decision_engine.py#L36-L120) |

### IPS Module
| [response.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/ips/response.py) | IPSModule nftables + iptables fallback, whitelist auto-detect | [L54-L300+](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/ips/response.py) |
| [models.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/ips/models.py) | AlertEvent dataclass | [L11-L46](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/ips/models.py#L11-L46) |

### Database Module
| [connection.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/connection.py) | Async SQLAlchemy SQLite engine (WAL off) | [L17-L48](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/connection.py#L17-L48) |
| [crud.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/crud.py) | Async CRUD alerts, blocked IPs, traffic, rules. Retention cleanup function (never called) | [L25-L250](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/crud.py#L25-L250) |
| [models.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/models.py) | 5 ORM tables (alerts, blocked, traffic, config_hist, signature_rules) | [L19-L154](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/models.py#L19-L154) |

### API Backend Module
| [main.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/main.py) | FastAPI app, CORS *, zero auth, auto-unblock task (IPSModule attachment hack via getattr) | [L28-L139](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/main.py#L28-L139) |
| [websocket.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/websocket.py) | WS manager broadcast tanpa keep-alive / per-topic | [L13-L48](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/websocket.py#L13-L48) |
| [routers/config.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/routers/config.py) | Config PUT endpoint (TIDAK persist ke file TOML, requires_restart pendek) | [L18-L42](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/routers/config.py#L18-L42) |
| [routers/blocked_ips.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/routers/blocked_ips.py) | Block/unblock endpoint (ips_module via getattr hack) | [L45-L47](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/routers/blocked_ips.py#L45-L47) |
| [routers/alerts.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/routers/alerts.py) | Alert list endpoint (pagination + filter) | [L16-L38](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/routers/alerts.py#L16-L38) |

### Frontend Dashboard
| [Overview.jsx](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/dashboard/src/pages/Overview.jsx) | Overview page stats cards + charts + alert table (campuran Inggris label) | [L96-L250](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/dashboard/src/pages/Overview.jsx#L96-L250) |
| [Settings.jsx](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/dashboard/src/pages/Settings.jsx) | Settings page (flat form, tidak ada whitelist editor) | [L43-L170](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/dashboard/src/pages/Settings.jsx#L43-L170) |

### Test Suite
| [test_api.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/tests/test_api.py) | API async test httpx ASGITransport (6 test case) | [L22-L75](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/tests/test_api.py#L22-L75) |
| [mock_flows.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/tests/fixtures/mock_flows.py) | 5 mock flow vectors (normal, syn flood, brute force, icmp flood, exfiltration) | [L5-L158](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/tests/fixtures/mock_flows.py#L5-L158) |

---

> **PENUTUP:** Dokumen ini bisa langsung digunakan sebagai backlog pekerjaan (copy paste ke Trello / GitHub Issues). Setiap tugas memiliki ID unik, link referensi source code, penjelasan mengapa perlu diperbaiki, dan step by step implementasi detail yang bisa dieksekusi oleh Junior Dev atau AI Agent tanpa perlu analisis ulang. 
>
> Mulai dari FASE 1, urutkan tugas berdasarkan kolom Prioritas: 🔴 MUST dikerjakan SEMUA sebelum Fase 1 selesai. 🟠 SHOULD boleh sebagian, tapi usahakan semua. 🟡 COULD nice to have, boleh di-skip jika waktu terbatas.
