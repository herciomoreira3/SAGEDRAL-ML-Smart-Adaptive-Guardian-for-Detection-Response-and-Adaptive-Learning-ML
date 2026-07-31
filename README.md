<div align="center">

# 🛡️ SAGEDRAL-ML

### Sistema Intelijente ba Detesaun, Prevensaun no Aprendizajen Adaptativu iha Rede

### *(Smart Adaptive Guardian for Enhanced Detection, Response, and Adaptive Learning — ML)*

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20%2B%20WebSocket-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![LightGBM](https://img.shields.io/badge/LightGBM-ML-5C913B)](https://lightgbm.readthedocs.io/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Linux](https://img.shields.io/badge/Plataforma-Linux-FCC624?logo=linux&logoColor=black)](https://www.kernel.org/)
[![Versaun](https://img.shields.io/badge/Versaun-1.0.0-blue)](https://github.com/herciomoreira3/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML)
![Lisensa](https://img.shields.io/badge/Lisensa-MIT-green)

*Deteta. Prevene. Adapta.*

</div>

---

## 📖 Kona-ba SAGEDRAL-ML

**SAGEDRAL-ML** mak Network Intrusion Detection and Prevention System (NIDPS)
ba Linux. Sistema kaptura tráfiku rede, agrega pakote ba flow, kombina regra
assinatura ho modelu LightGBM, blokeia fonte ameasa no aprezenta eventu iha
dashboard web Tetun.

Projetu ida-ne'e dezenhadu ba lab, server no gateway inline, ho objetivu atu
fó detesaun híbrida ne'ebé transparente, auditável no bele adapta.

---

## 🚀 Kapasidade Prinsipál

| Área | Kapasidade |
|---|---|
| 🔍 Detesaun | Signature DSL + LightGBM anomalia no klasifikasaun |
| 🧱 Prevensaun | nftables, iptables, block CIDR, whitelist no auto-unblock |
| 📡 Kaptura | Scapy, libpcap no AF_PACKET |
| 📊 Dashboard | React, WebSocket, alerta, tráfiku, audit no informasaun modelu |
| 🔐 Seguransa | JWT, RBAC, rate limit no systemd capability mínimu |
| 🧠 Adaptasaun | Feedback, retraining quality gate no drift PSI |
| 💾 Dadus | SQLite/WAL, PostgreSQL, Alembic, backup no restore |
| 🔔 Integrasaun | CEF syslog, webhook, email, Telegram no GeoIP |
| 📈 Operasaun | Prometheus, Grafana, Docker, Nginx TLS no HA basic |

---

## 🏗️ Arkitetura Badak

```text
Rede
  │
  ▼
Capture ──► Flow/Feature 28 ──► Signature + LightGBM
                                      │
                                      ▼
                               Decision Engine
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                      Firewall     Database     Integrasaun
                         └────────────┼────────────┘
                                      ▼
                            FastAPI + WebSocket
                                      │
                                      ▼
                               Dashboard React
```

---

## 🛠️ Tech Stack

| Kategoria | Teknolojia |
|---|---|
| Linguajen | Python `3.8+`, JavaScript |
| Machine Learning | LightGBM, scikit-learn, pandas, NumPy |
| Packet capture | Scapy, libpcap, Linux AF_PACKET |
| Backend | FastAPI, Uvicorn, WebSocket |
| Frontend | React 18, Vite 5, Tailwind CSS 3, Recharts |
| Database | SQLite, SQLAlchemy async, PostgreSQL, Alembic |
| IPS | nftables ho iptables fallback |
| Operasaun | systemd, Docker Compose, Nginx, Prometheus, Grafana |

---

## ⚙️ Instalasaun Lalais

### Pre-rekizitu

- Ubuntu/BackBox 20.04 ka Linux kompatível;
- Python `3.8+`;
- `sudo`;
- NIC ne'ebé bele kaptura tráfiku.

### Instala

```bash
git clone https://github.com/herciomoreira3/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML.git
cd SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML
sudo bash scripts/install.sh
```

### Konfigura no verifika

```bash
sudo nano /etc/sagedral/config.toml
sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml config validate
sudo systemctl restart sagedral-ml
sagedral-ml health
sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml model info
```

Password admin dahuluk:

```bash
sudo cat /var/lib/sagedral-ml/.sagedral-admin-secret
sagedral-ml login --username admin
```

Dashboard default: `http://127.0.0.1:8000`.

> Antes ativa IPS inline, hatama gateway, management IP no subnet interna iha
> whitelist. Haree prosedimentu kompletu iha
> [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

---

## 🧠 Training CICIDS

Pipeline suporta CSV ida ka diretóriu rekursivu husi:

- [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html);
- [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html).

Ezemplu:

```bash
sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml train \
  --dataset /var/lib/sagedral-ml/datasets/cicids2017 \
  --save-dir /var/lib/sagedral-ml/models \
  --train-test-split 0.2 \
  --max-rows-per-class 100000

sudo systemctl restart sagedral-ml
sagedral-ml model info
```

Metrika fallback mak synthetic deit. Akurásia/F1 real iha dashboard mai husi
metadata modelu depois training. Guia download, kapasidade RAM, kombinasaun
dataset no validasaun iha
[`docs/RUNBOOK.md`](docs/RUNBOOK.md#7-training-modelu-cicids20172018).

---

## 🐳 Docker

```bash
docker compose up -d --build
docker compose ps
```

Container presiza `NET_RAW`, `NET_ADMIN` no host networking. Uza deit iha
Linux host ne'ebé konfiável.

---

## 🧪 Dezenvolvimentu

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -e ".[dev]"
pytest -q
```

Build dashboard:

```bash
cd sagedral_ml/dashboard
npm ci
npm run build
```

---

## 📚 Dokumentasaun

| Dokumentu | Konteúdu |
|---|---|
| [`docs/prd.md`](docs/prd.md) | Vizaun produtu, rekizitu, arkitetura, estatutu fitur, gap no roadmap |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Topolojia, instalasaun, konfigurasaun, training, operasaun, DR no troubleshooting |

README ne'e deliberadamente badak. `prd.md` mak fonte verdade ba produtu;
`RUNBOOK.md` mak fonte verdade ba komandu no operasaun.

---

## ⚠️ Nota Production

- Fallback modelu ajuda startup, maibé la'ós modelu production.
- Dashboard/API external tenke liu husi HTTPS reverse proxy.
- Inline gateway presiza console access, backup no rollback plan.
- Throughput `1 Gbps` la garantidu sem benchmark/soak test iha hardware alvu.
- Hala'o teste seguransa deit iha rede ne'ebé ita iha autorizasaun.

---

## 📜 Lisensa

Projetu ida-ne'e uza lisensa MIT tuir metadata package.

<div align="center">

Harii ho ❤️ ba seguransa dijitál no aprendizajen teknologia iha Timor-Leste.

**SAGEDRAL-ML** — *Deteta. Prevene. Adapta.*

</div>
