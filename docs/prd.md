# SAGEDRAL-ML — Dokumentu Rekizitu Produtu

> **S**mart **A**daptive **G**uardian for **E**nhanced **D**etection, **R**esponse, and **A**daptive **L**earning — **ML**
>
> Versaun dokumentu: `2.0`
>
> Versaun produtu: `1.0.0`
>
> Atualizasaun ikus: `2026-07-31`
>
> Plataforma alvu: `GNU/Linux`

---

## 1. Objetivu dokumentu

Dokumentu ida-ne'e sai fonte ida deit ba:

- vizaun no objetivu produtu;
- rekizitu funsionál no la-funsionál;
- arkitetura no kontratu tekniku;
- estatutu implementasaun atual;
- limitasaun ne'ebé seidauk rezolve;
- kritériu aseitasaun no prioridade dezenvolvimentu.

Dokumentu ida-ne'e konsolida informasaun husi `prd.md`, `update.md`,
`UPDATE_IMPLEMENTATION_STATUS.md` no `implementation_plan.md` antigu. Komandu
operasionál, instalasaun, topolojia rede no troubleshooting muda ba
[`RUNBOOK.md`](RUNBOOK.md).

### 1.1 Legenda estatutu

| Símbolu | Estatutu | Signifikadu |
|---|---|---|
| ✅ | Disponível | Implementa ona iha kódigu produtu |
| 🟡 | Parsial | Implementa, maibé presiza validasaun ka kapasidade tan |
| ⬜ | Seidauk disponível | Seidauk implementa |
| 🚫 | La tama iha v1 | Deliberadamente la tama iha eskopu versaun 1 |

---

## 2. Vizaun produtu

SAGEDRAL-ML mak sistema **Network Intrusion Detection and Prevention System
(NIDPS)** ne'ebé bele instala iha Linux. Sistema kaptura tráfiku rede, transforma
pakote ba flow, deteta ameasa ho assinatura no Machine Learning, halo desizaun,
blokeia orijen ameasa, rai evidénsia no aprezenta rezultadu iha dashboard web.

### 2.1 Proposta valor

| Kapasidade | Valor ba uza-na'in |
|---|---|
| Detesaun híbrida | Kombina regra assinatura ho anomalia LightGBM |
| Prevensaun | Blokeia IP/CIDR liu husi nftables ka iptables |
| Observabilidade | Dashboard, audit log, métrika Prometheus no log estruturadu |
| Adaptasaun | Feedback, drift PSI no training modelu foun |
| Operasaun simples | CLI, instalador, systemd, backup no restore |
| Efisiénsia | Python/LightGBM, SQLite default no backend kaptura hili-na'in |

### 2.2 Prinsípiu dezenhu

- **Seguru:** input validasaun, whitelist, JWT, RBAC no priviléjiu mínimu.
- **Modulár:** capture, feature, detection, IPS, API no dashboard separadu.
- **Auditável:** desizaun, alterasaun no asaun uza-na'in iha rastu.
- **Fail-safe:** fallback modelu bele halo servisu kontinua, maibé la konsidera
  hanesan modelu produsaun.
- **Instalável:** suporta instalasaun husi Git/Python package no systemd.
- **Kompatível:** Python `3.8+` iha Linux, ho dependénsia pin ne'ebé suporta
  Ubuntu/BackBox 20.04.

---

## 3. Uza-na'in alvu

### 3.1 Papél sistema

| Papél | Responsabilidade |
|---|---|
| Viewer | Haree dashboard, alerta, tráfiku no informasaun modelu |
| Analyst | Halo investigasaun, feedback, taka alerta no block/unblock |
| Admin | Jere konfigurasaun, regra, whitelist, uza-na'in, audit no training |

### 3.2 Ambiente alvu

| Rekizitu | Mínimu | Rekomendadu |
|---|---|---|
| Sistema operativu | Ubuntu/BackBox 20.04 | Ubuntu 22.04 LTS ka foun liu |
| CPU | 2 core | 4 core ka liu |
| RAM runtime | 4 GB | 8 GB ka liu |
| RAM training | 8 GB | 16–32 GB tuir dataset |
| Disku | 10 GB | 50 GB ka liu ba dataset/backup |
| Python | 3.8.10 | 3.11 iha sistema kompatível |
| Rede | NIC ida | NIC rua ba gateway inline |
| Priviléjiu | `sudo` ba instalasaun | user service `sagedral` ho capabilities |

---

## 4. Eskopu no limitasaun

### 4.1 Eskopu versaun 1

- Kaptura pakote real-time iha interface Linux.
- Agregasaun flow no estrasaun feature 28.
- Detesaun assinatura, anomalia no klasifikasaun atake.
- Desizaun híbrida no resposta IPS.
- Persisténsia SQLite ka PostgreSQL.
- REST API, WebSocket, dashboard Tetun no autentikasaun.
- Integrasaun SIEM, webhook, email, Telegram no GeoIP.
- Backup, restore, migrasaun, monitoring, Docker no HA basic.
- Training CICIDS2017/CSE-CIC-IDS2018.

### 4.2 La tama iha eskopu v1

| Kapasidade | Estatutu |
|---|---|
| Deep Packet Inspection ba konteúdu layer 7 | 🚫 |
| Dekriptasaun tráfiku TLS | 🚫 |
| Aplikasaun móvel | 🚫 |
| GPU inference | 🚫 |
| SaaS/cloud control plane | 🚫 |
| Runtime nativu Windows/macOS | 🚫 |
| Garantia throughput 1 Gbps ba hardware hotu | 🚫 |

---

## 5. Arkitetura sistema

```text
Interface rede
     │
     ▼
Capture: Scapy / libpcap / AF_PACKET
     │ pakote
     ▼
Flow Aggregator + feature 28
     │ flow
     ├──────────────┐
     ▼              ▼
Signature Engine   LightGBM Engine
     │              │
     └──────┬───────┘
            ▼
      Decision Engine
            │
     ┌──────┼──────────┐
     ▼      ▼          ▼
 Firewall  Database   Integrasaun
     │      │          │
     └──────┴────┬─────┘
                 ▼
        FastAPI + WebSocket
                 │
                 ▼
          Dashboard React
```

### 5.1 Pipeline

1. Capture backend simu pakote husi NIC.
2. Flow aggregator grupu pakote tuir 5-tuple.
3. Flow remata tuir FIN/RST, timeout ka limite pakote.
4. Sistema kalkula feature 28.
5. Signature engine no ML engine avalia flow.
6. Decision engine kombina pontuasaun.
7. Se passa `alert_threshold`, sistema kria alerta.
8. Se passa `block_threshold` no IPS ativu, sistema blokeia orijen.
9. Database, audit, WebSocket no integrasaun simu eventu.

### 5.2 Modelu thread/process

- Main process jere lifecycle.
- Capture thread simu pakote.
- Processing worker transforma no deteta flow.
- FastAPI hala'o iha event loop async.
- Integrasaun external uza worker limitadu.
- `performance.detection_workers > 1` ativa process pool ba inferénsia.

---

## 6. Teknolojia

| Área | Teknolojia | Versaun/nota |
|---|---|---|
| Linguajen backend | Python | `>=3.8` |
| Kaptura | Scapy, libpcap, AF_PACKET | backend konfigurável |
| Machine Learning | LightGBM, scikit-learn | modelu etapa rua |
| API | FastAPI + Uvicorn | REST, WebSocket, OpenAPI |
| Database | SQLite + SQLAlchemy async | default |
| Database enterprise | PostgreSQL + asyncpg | opsionál |
| Migrasaun | Alembic | schema versionadu |
| Dashboard | React 18 + Vite 5 | SPA |
| Estilu UI | Tailwind CSS 3 | dashboard responsivu |
| Gráfiku | Recharts | métrika no tráfiku |
| Firewall | nftables | preferidu |
| Firewall fallback | iptables | kompatibilidade |
| Monitoring | Prometheus + Grafana | template iha `deploy/` |
| Reverse proxy | Nginx | TLS, CSP, HSTS |
| HA | Keepalived + peer sync | active-passive basic |
| Container | Docker + Compose | `NET_RAW`, `NET_ADMIN` |

---

## 7. Rekizitu funsionál no estatutu

### 7.1 Capture

| ID | Rekizitu | Estatutu |
|---|---|---|
| CAP-01 | Kaptura non-blocking ho Scapy | ✅ |
| CAP-02 | Backend libpcap | ✅ |
| CAP-03 | Backend AF_PACKET TPACKET_V2/PACKET_RX_RING | ✅ |
| CAP-04 | Filtro BPF | ✅ |
| CAP-05 | Capture statistics, queue drop no kernel drop | ✅ |
| CAP-06 | Watchdog no auto-recovery | ✅ |
| CAP-07 | Promiscuous mode konfigurável | ✅ |

### 7.2 Feature extraction

| ID | Rekizitu | Estatutu |
|---|---|---|
| FEAT-01 | Agrega flow bazeia ba 5-tuple | ✅ |
| FEAT-02 | Feature estatístiku 28 | ✅ |
| FEAT-03 | Running statistics atu limita memória | ✅ |
| FEAT-04 | IPv4 no IPv6 | ✅ |
| FEAT-05 | Limite active flow no LRU-style eviction | ✅ |
| FEAT-06 | Timeout no max packet per flow | ✅ |

### 7.3 Detesaun

| ID | Rekizitu | Estatutu |
|---|---|---|
| DET-01 | Regra assinatura default | ✅ |
| DET-02 | Regra custom JSON/TOML ho DSL AST seguru | ✅ |
| DET-03 | Regra database hot reload | ✅ |
| DET-04 | Threshold per-rule no source whitelist override | ✅ |
| DET-05 | LightGBM binary anomaly detector | ✅ |
| DET-06 | LightGBM multiclass classifier | ✅ |
| DET-07 | Fallback synthetic/rule-based | ✅ |
| DET-08 | Hybrid weighted decision | ✅ |
| DET-09 | Dedup alerta no severity override | ✅ |
| DET-10 | Feedback no adaptive retraining quality gate | ✅ |
| DET-11 | Drift monitoring ho PSI | ✅ |

### 7.4 IPS

| ID | Rekizitu | Estatutu |
|---|---|---|
| IPS-01 | Block/unblock IPv4 liu husi nftables | ✅ |
| IPS-02 | iptables fallback | ✅ |
| IPS-03 | Whitelist IP no CIDR IPv4/IPv6 | ✅ |
| IPS-04 | Auto-unblock | ✅ |
| IPS-05 | Strike-based escalation | ✅ |
| IPS-06 | Block CIDR administrativu | ✅ |
| IPS-07 | Sliding-window connection rate limiter | ✅ |
| IPS-08 | Reconcile database blocklist ba firewall | ✅ |

### 7.5 API, autentikasaun no dashboard

| ID | Rekizitu | Estatutu |
|---|---|---|
| API-01 | JWT login/logout no bootstrap admin seguru | ✅ |
| API-02 | RBAC viewer/analyst/admin | ✅ |
| API-03 | Rate limiting | ✅ |
| API-04 | Structured JSON error/log | ✅ |
| API-05 | REST API no OpenAPI | ✅ |
| API-06 | WebSocket auth, keepalive, topic no ring buffer | ✅ |
| API-07 | Health, readiness no metrics | ✅ |
| UI-01 | Dashboard React iha lian Tetun | ✅ |
| UI-02 | Alerts, filter, pagination no CSV export | ✅ |
| UI-03 | Traffic, model, settings, blocked IP no whitelist | ✅ |
| UI-04 | Audit log no jestaun uza-na'in | ✅ |
| UI-05 | Confirmation ba asaun destrutivu | ✅ |

### 7.6 Database, integrasaun no deployment

| ID | Rekizitu | Estatutu |
|---|---|---|
| DB-01 | SQLite async ho WAL no index | ✅ |
| DB-02 | Retention scheduler | ✅ |
| DB-03 | Backup/restore no archive hardening | ✅ |
| DB-04 | Alembic migration | ✅ |
| DB-05 | PostgreSQL/`pg_dump` | ✅ |
| INT-01 | CEF syslog no webhook Slack/Teams-compatible | ✅ |
| INT-02 | Email no Telegram | ✅ |
| INT-03 | GeoIP MaxMind | ✅ |
| OPS-01 | systemd hardening no watchdog | ✅ |
| OPS-02 | Docker/Compose | ✅ |
| OPS-03 | Prometheus/Grafana template | ✅ |
| OPS-04 | Nginx TLS/CSP/HSTS template | ✅ |
| OPS-05 | Keepalived active-passive no peer blocklist sync | ✅ |

---

## 8. Rekizitu Machine Learning

### 8.1 Arkitetura etapa rua

| Etapa | Objetivu | Métrika |
|---|---|---|
| 1 | `NORMAL` kontra anomalia | accuracy no F1 |
| 2 | Klasifika tipu atake | multiclass accuracy |

### 8.2 Feature entrada

Modelu simu feature 28 tuir mai:

```text
duration, total_fwd_packets, total_bwd_packets,
total_fwd_bytes, total_bwd_bytes,
fwd_packet_len_mean, fwd_packet_len_std,
bwd_packet_len_mean, bwd_packet_len_std,
flow_bytes_per_sec, flow_packets_per_sec,
fwd_iat_mean, fwd_iat_std, bwd_iat_mean, bwd_iat_std,
psh_flag_count, urg_flag_count, syn_flag_count,
fin_flag_count, rst_flag_count, ack_flag_count,
avg_fwd_segment_size, avg_bwd_segment_size,
fwd_header_len, bwd_header_len, down_up_ratio,
protocol, dst_port
```

### 8.3 Taxonomia runtime

```text
NORMAL
DDoS
PortScan
BruteForce
DoS_Slowloris
WebAttack
Botnet
Infiltration
Exfiltration
```

Variasaun DoS `Hulk`, `GoldenEye`, `SlowHTTPTest` no `Slowloris` tama iha
bucket runtime `DoS_Slowloris`. Label ne'ebé taxonomia runtime seidauk suporta,
hanesan `Heartbleed`, sei drop ho kontajen iha metadata; ida-ne'e backlog
taxonomia, la'ós erro silenciosu.

### 8.4 Dataset training

| Dataset | Uzu | Fonte |
|---|---|---|
| CICIDS2017 | Dataset prinsipál | [UNB CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) |
| CSE-CIC-IDS2018 | Dataset suplementár | [UNB CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) |

Pipeline training tenke:

- simu CSV ida ka diretóriu ho scan rekursivu;
- mapea header CICFlowMeter 2017/2018 ba feature runtime;
- konverte duration/IAT raw CICFlowMeter husi microsecond ba second;
- la konverte koluna canonical SAGEDRAL dala rua;
- normaliza label 2017/2018;
- prosesu CSV iha chunk;
- limita memória ho `max_rows_per_class`;
- halo split stratified ho random state determinístiku;
- rai métrika, distribuisaun klase no relatóriu import;
- rejeita dataset ne'ebé coverage feature menus ka classe la sufisiente.

### 8.5 Artefaktu modelu

Training hakerek artefaktu imutável ba:

```text
/var/lib/sagedral-ml/models/
├── active_model.json
└── versions/
    └── <version>-<uuid>/
        ├── anomaly_detector.pkl
        ├── attack_classifier.pkl
        ├── feature_names.json
        ├── model_profile.json
        └── model_metadata.json
```

Publikasaun modelu uza pointer `active_model.json` ho replace atómiku.
Runtime suporta estrutura legacy ne'ebé artefaktu iha model root bainhira pointer
seidauk iha. Resolver rejeita traversal no symlink ne'ebé sai husi model root.

### 8.6 Interpretasaun métrika

- Fallback metric mak validasaun synthetic deit.
- Metrika depois training mak stratified holdout dataset ne'ebé user fó.
- Holdout random la prova generalizasaun ba loron ka rede seluk.
- Antes produsaun, rezerva loron/dataset ne'ebé training la haree.
- Dashboard tenke hatudu `La disponível` se metadata métrika la iha ka inválidu,
  la bele inventa `0%`.

---

## 9. Kontratu API prinsipál

| Métodu | Endpoint | Aksesu |
|---|---|---|
| POST | `/api/v1/auth/login` | Públiku, rate-limited |
| GET | `/api/v1/status` | Públiku mínimu |
| GET | `/api/v1/status/details` | Login |
| GET | `/api/v1/capture/stats` | Login |
| GET | `/api/v1/alerts` | Login |
| GET | `/api/v1/alerts/export.csv` | Login |
| POST | `/api/v1/alerts/{id}/feedback` | Analyst/Admin |
| POST | `/api/v1/alerts/{id}/close` | Analyst/Admin |
| GET/POST/DELETE | `/api/v1/whitelist` | Login/Admin/Admin |
| GET/POST/PUT/DELETE | `/api/v1/rules` | Login/Admin/Admin/Admin |
| GET/POST/PUT/DELETE | `/api/v1/users` | Admin |
| GET | `/api/v1/audit-logs` | Admin |
| GET | `/api/v1/model/info` | Login |
| GET | `/api/v1/model/drift` | Login |
| POST | `/api/v1/model/reload` | Admin |
| POST | `/api/v1/feedback/retrain` | Admin |
| GET | `/healthz`, `/readyz`, `/metrics` | Monitoring |
| WS | `/ws/alerts?token=<JWT>` | JWT ativu |

FastAPI OpenAPI/Swagger disponível iha `/docs`.

---

## 10. Konfigurasaun no path sistema

### 10.1 Ordem konfigurasaun

1. Environment variables `SAGEDRAL_*`.
2. `/etc/sagedral/config.toml`.
3. Default internu.

### 10.2 Path importante

| Rekursu | Path |
|---|---|
| Konfigurasaun | `/etc/sagedral/config.toml` |
| Data runtime | `/var/lib/sagedral-ml/` |
| Modelu | `/var/lib/sagedral-ml/models/` |
| Database SQLite | `/var/lib/sagedral-ml/sagedral.db` |
| Backup | `/var/lib/sagedral-ml/backups/` |
| Regra custom | `/var/lib/sagedral-ml/custom-rules/` |
| Secret admin bootstrap | `/var/lib/sagedral-ml/.sagedral-admin-secret` |
| Secret JWT | `/var/lib/sagedral-ml/.sagedral-jwt-secret` |
| Log | `/var/log/sagedral-ml.log` no journal systemd |
| Service | `/etc/systemd/system/sagedral-ml.service` |

---

## 11. Rekizitu la-funsionál

### 11.1 Seguransa

- Service hala'o hanesan user dedicated `sagedral`.
- Systemd fó deit `CAP_NET_RAW` no `CAP_NET_ADMIN`.
- `NoNewPrivileges`, filesystem protection no kernel hardening ativu.
- Password hash, JWT secret persistente no bootstrap secret permission ketak.
- IP/CIDR validasaun obrigatóriu antes firewall subprocess.
- Python arbitrary execution la permite iha custom rule.
- Backup/restore rejeita path traversal no link archive.
- API external tenke liu husi TLS reverse proxy.

### 11.2 Fiabilidade

- Queue bounded no packet-drop statistics.
- Capture watchdog.
- Database WAL no retention.
- Model publication atómiku.
- Backup antes upgrade.
- Health, readiness no systemd watchdog.
- Fallback modelu permite startup, maibé produsaun tenke modelu trained.

### 11.3 Performance

- `max_active_flows` proteje memória.
- Backend capture bele hili tuir throughput.
- Batch inference no process pool disponível.
- Target real depende NIC, CPU, kernel, traffic mix no konfigurasaun.
- Reklame `1 Gbps` presiza benchmark no soak test iha hardware alvu.

### 11.4 Observabilidade

- JSON logging.
- Audit log ba asaun sensível.
- Capture/kernel drop statistics.
- Prometheus metrics no alert template.
- Drift PSI no model metadata.

---

## 12. Estatutu produtu atual

### 12.1 Implementa ona

Fase 1 hotu implementa: authentication, persistent config, firewall reconcile,
rule DSL, capture watchdog, feature optimization, rate limit, Tetun UI, model
fallback, systemd hardening no CI.

Fase 2 implementa hotu ezetu acceptance coverage 80%: audit, SIEM,
notification, adaptive learning, drift, GeoIP, RBAC, WebSocket, Alembic,
multiprocessing, libpcap, Docker, monitoring no PCAP replay.

Fase 3 implementa HA basic, PostgreSQL, AF_PACKET, rate limiter, CIDR block,
flow cap, TLS/Nginx, fine-grained permission, user management no performance
profiling.

Training CICIDS2017/2018, metadata métrika no active model pointer implementa
ona iha pipeline atual.

### 12.2 Seidauk kompletu

| ID | Gap | Estatutu/aseitasaun |
|---|---|---|
| GAP-01 | Coverage total 80% | 🟡 Audit ikus rejista 41%; tenke aumenta no mede fali |
| GAP-02 | Separasaun literal ba daemon capture/core/API ho UDS | ⬜ Agora service ida ho user/capability mínimu |
| GAP-03 | Taxonomia `Heartbleed` | ⬜ Importer relata/drop; presiza classe runtime no test |
| GAP-04 | Training full CICIDS iha hardware Linux alvu | 🟡 Pipeline/smoke passa; full corpus seidauk valida iha ambiente alvu |
| GAP-05 | Validasaun kernel/integrasaun external | 🟡 Presiza nftables, AF_PACKET, PostgreSQL, TLS, HA, SIEM no notification real |
| GAP-06 | Soak test throughput organizasaun | ⬜ Presiza mínimu 24 oras ho traffic representativu |

### 12.3 Riska residual

- Fallback synthetic bele halo uza-na'in konfunde ho modelu produsaun; UI no
  metadata tenke kontinua fó nota klaru.
- Configurasaun threshold sala bele aumenta false positive ka ameasa ne'ebé
  la deteta.
- Inline gateway bele interrompe rede se route/NAT/whitelist sala.
- HA template la substitui teste failover.
- Dataset benchmark la reprezenta automaticamente rede organizasaun.

### 12.4 Evidénsia validasaun atual

| Validasaun | Rezultadu | Limite |
|---|---|---|
| Test training, ML engine, CLI no API | `60 passed` iha Python 3.9 | Manifest alvu, la'ós coverage full |
| Smoke training LightGBM | Pasa; pointer kria no MLEngine load version ativu | Dataset synthetic ki'ik |
| Review publikasaun modelu | Aprova; traversal, symlink no fsync failure testadu | Durabilidade diretóriu Windows best-effort |
| Coverage total audit ikus | `41%` | Seidauk atinji alvu `80%` |
| Full CICIDS training | Seidauk hala'o iha hardware alvu | Presiza validasaun Linux |

---

## 13. Roadmap prioridade

### P0 — Antes produsaun

- Train modelu ho CICIDS2017 no suplementu CICIDS2018.
- Avalia ho dataset/loron ne'ebé la tama training.
- Test nftables/iptables, AF_PACKET no capability iha Linux alvu.
- Rotasaun secret no ativa TLS.
- Test backup restore no rollback.
- Soak test no define limite packet drop.

### P1 — Kualidade

- Aumenta coverage ba mínimu 80%.
- Aumenta test CLI, orchestrator, adapter Linux no failure mode.
- Decide suporte runtime ba `Heartbleed`.
- Halo PCAP regression ho ground truth organizasaun.

### P2 — Hardening avansadu

- Separa capture, core no API ba process/daemon ho IPC autenticadu.
- Automatiza release artifact/wheel no supply-chain checks.
- Halo HA failover no database replication exercise periódiku.

---

## 14. Kritériu aseitasaun release

Release bele tama inline produsaun deit se:

- test unit/integration ne'ebé afeta mudansa hotu pasa;
- dashboard build pasa;
- config validate no database migrate pasa;
- modelu trained bele load no metadata métrika hatudu iha CLI/dashboard;
- replay PCAP atinji precision/recall ne'ebé organizasaun aprova;
- packet no kernel drop iha limite;
- whitelist inklui gateway, management no monitoring address;
- backup restore test ona iha node izoladu;
- TLS, RBAC no secret production konfiguradu;
- failover, rollback no response incident simu evidénsia;
- fallback la uza hanesan modelu production.

Detallu komandu no prosedimentu ba kritériu sira-ne'e iha
[`RUNBOOK.md`](RUNBOOK.md).
