# Implementation Plan — SAGEDRAL-ML (NIDPS Machine Learning System)

SAGEDRAL-ML is a lightweight, installable Network Intrusion Detection and Prevention System (NIDPS) built for Linux environments. This document outlines the step-by-step technical implementation plan to build the entire system based on the locked architecture in [prd.md](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/prd.md).

---

## User Review Required

> [!IMPORTANT]
> - **Execution Target**: The full codebase will be implemented inside the Python package structure `sagedral_ml/` and React SPA `sagedral_ml/dashboard/`.
> - **Environment & Dependencies**: The implementation will prepare all standard Python package definitions (`pyproject.toml`) and Node.js setup (`package.json`) required for execution.
> - **Security Controls**: All subprocess interactions with `nftables`/`iptables` will strictly validate IP addresses using Python's `ipaddress` module and enforce strict local/gateway whitelist rules to prevent self-blocking.

---

## Proposed Changes

### 1. Repository Structure & Configuration Layer

#### [NEW] [pyproject.toml](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/pyproject.toml)
- Package configuration with `hatchling` build backend.
- Dependencies: `scapy`, `lightgbm`, `fastapi`, `uvicorn`, `sqlalchemy`, `aiosqlite`, `click`, `dpkt`, `psutil`, `joblib`, `scikit-learn`.
- Console script entrypoint: `sagedral-ml = sagedral_ml.cli:main`.

#### [NEW] [sagedral_ml/__init__.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/__init__.py)
- Package metadata (`__version__ = "1.0.0"`).

#### [NEW] [sagedral_ml/config.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/config.py)
- TOML configuration loader using standard library `tomllib`/`tomli`.
- Environment variable overrides (`SAGEDRAL_<SECTION>_<KEY>`).
- Singleton config manager and default TOML template generator.

---

### 2. Data & Database Layer

#### [NEW] [sagedral_ml/database/connection.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/connection.py)
- Async SQLAlchemy engine initialization (`sqlite+aiosqlite:////var/lib/sagedral-ml/sagedral.db`).
- Session factory and FastAPI dependency `get_db()`.

#### [NEW] [sagedral_ml/database/models.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/models.py)
- SQLAlchemy ORM models: `Alert`, `BlockedIP`, `TrafficStat`, `ConfigHistory`, `SignatureRule`.

#### [NEW] [sagedral_ml/database/crud.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/database/crud.py)
- Async CRUD methods for alert creation/querying, IP block/unblock list management, traffic stats recording, and rule management.

---

### 3. Feature Extraction & Detection Core

#### [NEW] [sagedral_ml/features/models.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/features/models.py)
- `FlowRecord` dataclass for 5-tuple flow aggregation.
- `to_feature_vector()` method generating exact 28 numeric features (duration, pkt/byte counts, IAT stats, TCP flags, segment sizes, headers, ratio, protocol, dst_port).

#### [NEW] [sagedral_ml/features/extractor.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/features/extractor.py)
- `FlowAggregator`: Thread-safe flow tracker that converts raw Scapy packets into complete `FlowRecord` instances based on TCP FIN/RST flags, timeouts, and max packet thresholds.

#### [NEW] [sagedral_ml/detection/rules/default_rules.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/rules/default_rules.py)
- Default signature rules dictionary (`SIG-001` to `SIG-007` covering SYN Flood, PortScan, ICMP Flood, Exfiltration, SSH/RDP BruteForce, and UDP Flood).

#### [NEW] [sagedral_ml/detection/signature_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/signature_engine.py)
- Rule-based detection evaluator generating `SignatureResult` with normalized severity scores.

#### [NEW] [sagedral_ml/detection/ml_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/ml_engine.py)
- `MLEngine`: LightGBM two-stage inference (Stage 1: Binary Anomaly Detection, Stage 2: Multiclass Attack Classifier). Includes graceful fallback when models are not loaded.

#### [NEW] [sagedral_ml/detection/decision_engine.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/detection/decision_engine.py)
- `DecisionEngine`: Hybrid score formula `(0.4 * signature) + (0.6 * ML)`, severity override logic, threshold evaluation, and alert deduplication window.

---

### 4. Capture & IPS Response Engine

#### [NEW] [sagedral_ml/capture/sniffer.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/capture/sniffer.py)
- `PacketCapture`: Non-blocking packet sniffer using Scapy's `AsyncSniffer` into thread-safe `queue.Queue`.

#### [NEW] [sagedral_ml/ips/response.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/ips/response.py)
- `IPSModule`: Direct execution of Linux firewall rules (`nftables` primary table setup & element management, `iptables` fallback).
- Hardcoded & configurable whitelist check (`127.0.0.1`, `::1`, default gateway, custom whitelist) and IP validation.

---

### 5. FastAPI Backend & Real-time WebSocket

#### [NEW] [sagedral_ml/api/schemas/](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/schemas/)
- Pydantic models for status, alerts, blocked IPs, traffic stats, configuration, rules, and model info.

#### [NEW] [sagedral_ml/api/websocket.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/websocket.py)
- `ConnectionManager`: Async WebSocket manager for broadcasting real-time alert events, traffic stats, and system status updates.

#### [NEW] [sagedral_ml/api/routers/](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/routers/)
- `alerts.py`: Paginated alert queries and filtering.
- `blocked_ips.py`: Manual block/unblock and active block list endpoints.
- `traffic.py`: Time-series traffic metrics.
- `config.py`: Configuration inspection and update endpoints.
- `model.py`: Model metadata and metric endpoints.
- `rules.py`: Custom rule management endpoints.

#### [NEW] [sagedral_ml/api/main.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/api/main.py)
- FastAPI application entrypoint, CORS configuration, static dashboard mount (`sagedral_ml/static`), and background auto-unblock worker.

---

### 6. React Dashboard SPA

#### [NEW] [sagedral_ml/dashboard/](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/dashboard/)
- React + Vite + Tailwind CSS + Recharts SPA.
- Pages: Overview, Alerts (with detail modal & CSV export), Blocked IPs (with manual block form), Traffic Analysis, Settings, and Model Info.
- Real-time updates via custom `useWebSocket` hook.
- Build production files into `sagedral_ml/static/`.

---

### 7. Orchestrator, CLI & Deployment Scripts

#### [NEW] [sagedral_ml/main.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/main.py)
- System orchestrator starting capture thread, processing worker thread, and FastAPI Uvicorn server with clean graceful shutdown.

#### [NEW] [sagedral_ml/cli.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/cli.py)
- Click CLI commands (`start`, `stop`, `status`, `restart`, `config`, `block`, `unblock`, `whitelist`, `alerts`, `model`, `install`).

#### [NEW] [scripts/install.sh](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/scripts/install.sh) & [scripts/uninstall.sh](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/scripts/uninstall.sh)
- Automated installer bash scripts setting up system packages, directories, nftables tables, and systemd service.

#### [NEW] [systemd/sagedral-ml.service](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/systemd/sagedral-ml.service)
- Systemd service file for auto-starting SAGEDRAL-ML daemon.

---

### 8. Scripts & Test Suite

#### [NEW] [sagedral_ml/scripts/train_model.py](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/sagedral_ml/scripts/train_model.py)
- Training pipeline for LightGBM anomaly detector and attack classifier models on CICIDS flow datasets.

#### [NEW] [tests/](file:///c:/Users/HP/Hercio/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML/tests/)
- Comprehensive unit and integration test suite:
  - `test_config.py`
  - `test_database.py`
  - `test_feature_extraction.py`
  - `test_signature_engine.py`
  - `test_ml_engine.py`
  - `test_decision_engine.py`
  - `test_ips.py`
  - `test_api.py`

---

## Verification Plan

### Automated Tests
- Run `pytest` across all test modules:
  ```bash
  pytest tests/ -v
  ```

### Manual & System Verification
- Validate package build and CLI commands:
  ```bash
  pip install -e .
  sagedral-ml config show
  sagedral-ml config validate
  ```
- Build React dashboard and verify static assets in `sagedral_ml/static`:
  ```bash
  cd sagedral_ml/dashboard && npm install && npm run build
  ```
- Test API status and WebSocket health endpoints using local test runner.
