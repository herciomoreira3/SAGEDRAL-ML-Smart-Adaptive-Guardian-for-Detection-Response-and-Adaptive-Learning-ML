# SAGEDRAL-ML — Runbook Instalasaun no Operasaun

> Guia ida-ne'e konsolida walkthrough, topolojia rede, instalasaun, training,
> operasaun loroloron, seguransa, backup, upgrade no troubleshooting.
>
> Versaun: `2.0`
>
> Atualizasaun ikus: `2026-07-31`

---

## 1. Regra seguransa antes hahú

SAGEDRAL-ML bele kaptura pakote no muda firewall. Sala konfigurasaun bele
interrompe koneksaun rede.

- Halo teste dahuluk iha VM, lab ka maintenance window.
- Asegura iha asesu console/VNC antes ativa IPS inline.
- Hatama gateway, management IP, monitoring IP no subnet administrasaun iha
  whitelist.
- Labele halo scan ka teste atake ba sistema ne'ebé ita la iha autorizasaun.
- Halo backup antes upgrade, restore ka mudansa firewall boot.
- Fallback modelu la'ós modelu production; train no avalia modelu real.
- Labele edita `active_model.json` ka version directory manualmente.

---

## 2. Pre-rekizitu

### 2.1 Sistema

```bash
uname -a
python3 --version
ip -brief address
ip route
```

Rekizitu prinsipál:

- Linux ho kernel `AF_PACKET`;
- Python `3.8+`;
- `sudo`;
- Git no internet ba instalasaun dependénsia;
- `libpcap`, `tcpdump`, `nftables`, `libgomp` no compiler;
- disk no RAM sufisiente ba dataset;
- Node.js 18 deit se hakarak build dashboard fali.

### 2.2 Port default

| Servisu | Port | Nota |
|---|---:|---|
| Dashboard/API | `8000/tcp` | Default FastAPI |
| Nginx HTTPS | `443/tcp` | Rekomendadu ba asesu external |
| Prometheus | `9090/tcp` | Se stack monitoring ativu |
| Grafana | `3000/tcp` | Se stack monitoring ativu |

---

## 3. Hili topolojia rede

### 3.1 Komparasaun

| Topolojia | Deteta | Blokeia tráfiku transit | Risku | Uzu |
|---|---|---|---|---|
| Gateway inline | Sin | Sin | Boot aas | Produksaun |
| Mirror/SPAN | Sin | La diretamente | Ki'ik | Monitorizasaun |
| Host IDS/IPS | Sin | Deit host ne'ebá | Klaru | Proteje server |
| Lab/VM/WSL | Sin, limitadu | La rekomenda | Ki'ik | Aprende/teste |

### 3.2 Gateway inline

```text
Internet ── WAN NIC [ SAGEDRAL-ML ] LAN NIC ── Switch ── Kliente
```

Gateway inline mak topolojia rekomendadu bainhira SAGEDRAL tenke haree no
blokeia tráfiku hotu. Host presiza NIC rua, IP forwarding, routing/NAT no
fail-open/failover plan.

Ezemplu prepara IP forwarding:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-sagedral-router.conf
sudo sysctl --system
```

Ezemplu NAT/forwarding ne'e presiza adapta ba interface real. Labele copy antes
konfirma `ip -brief address` no `ip route`.

```bash
SAGEDRAL_WAN_IFACE="enp0s3"
SAGEDRAL_LAN_IFACE="enp0s8"

sudo nft add table ip sagedral_nat
sudo nft 'add chain ip sagedral_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'
sudo nft add rule ip sagedral_nat postrouting oifname "$SAGEDRAL_WAN_IFACE" masquerade

sudo nft add table inet sagedral_forward
sudo nft 'add chain inet sagedral_forward forward { type filter hook forward priority filter; policy drop; }'
sudo nft add rule inet sagedral_forward forward \
  iifname "$SAGEDRAL_LAN_IFACE" oifname "$SAGEDRAL_WAN_IFACE" accept
sudo nft add rule inet sagedral_forward forward \
  iifname "$SAGEDRAL_WAN_IFACE" oifname "$SAGEDRAL_LAN_IFACE" \
  ct state established,related accept
```

Rai nftables tuir mekanizmu distro depois teste ona. SAGEDRAL jere tabela
blocklist nia rasik; routing/NAT mak responsabilidade administradór rede.

Konfigurasaun capture:

```toml
[capture]
interface = "enp0s3"
backend = "af_packet"
promiscuous = true

[ips]
enabled = true
whitelist = [
  "127.0.0.1",
  "::1",
  "192.168.10.0/24",
  "192.168.10.1"
]
```

### 3.3 Mirror/SPAN

```text
Internet ── Router ── Switch ── Kliente
                       │
                    SPAN port
                       │
                  SAGEDRAL-ML
```

SPAN permite detesaun pasivu, maibé firewall iha sensor la bele para tráfiku
ne'ebé la liu sensor. Hahu ho IDS-only:

```toml
[capture]
interface = "enp0s8"
promiscuous = true

[ips]
enabled = false
```

### 3.4 Host IDS/IPS

```text
Internet ── Firewall/Router ── Server + SAGEDRAL-ML
```

Uza interface server no BPF filter atu hamenus carga:

```toml
[capture]
interface = "eth0"
bpf_filter = "tcp port 22 or tcp port 80 or tcp port 443"

[ips]
enabled = true
```

### 3.5 Lab, VM no WSL

- VirtualBox/VMware: hili bridged adapter se presiza haree tráfiku LAN.
- NAT adapter deit normalmenti haree tráfiku VM rasik.
- WSL2 bele uza dashboard no no-capture mode, maibé promisc/firewall la hanesan
  Linux host real.
- Labele uza rezultadu WSL hanesan prova AF_PACKET/nftables production.

Hala'o UI deit ba teste:

```bash
sudo sagedral-ml start --no-capture
```

---

## 4. Instalasaun husi Git

### 4.1 Klona no instala

```bash
sudo apt-get update
sudo apt-get install -y git

git clone https://github.com/herciomoreira3/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML.git
cd SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML

sudo bash scripts/install.sh
```

Instalador:

- instala dependénsia sistema no Python;
- kria user service `sagedral`;
- kria config/data/log directories;
- inicializa nftables;
- inicializa fallback modelu;
- instala logrotate no systemd unit;
- enable no restart service.

### 4.2 Verifika instalasaun

```bash
command -v sagedral-ml
sagedral-ml --version
sudo systemctl status sagedral-ml --no-pager -l
sagedral-ml health
sagedral-ml model info
```

Se systemd la disponível, ezemplu iha container/WSL:

```bash
sudo sagedral-ml start
```

---

## 5. Konfigurasaun dahuluk

### 5.1 Identifika interface

```bash
ip -brief link
ip -brief address
ip route get 1.1.1.1
sudo tcpdump -D
```

Edita:

```bash
sudo nano /etc/sagedral/config.toml
```

Konfigurasaun mínimu:

```toml
[capture]
interface = "eth0"
backend = "scapy"       # scapy | libpcap | af_packet
bpf_filter = ""
promiscuous = true

[ips]
enabled = false         # Hahu false, ativa depois validasaun
preferred_backend = "nftables"
whitelist = ["127.0.0.1", "::1", "192.168.1.0/24"]

[api]
host = "127.0.0.1"      # Uza Nginx/TLS ba asesu external
port = 8000
```

### 5.2 Valida ho identidade service

```bash
sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml config validate

sudo systemctl restart sagedral-ml
sudo journalctl -u sagedral-ml -n 100 --no-pager -o cat
```

### 5.3 Login dahuluk

```bash
sudo cat /var/lib/sagedral-ml/.sagedral-admin-secret
sagedral-ml login --username admin
```

CLI husu password se `--password` la fó. Token lokal rai ho permission `0600`.
Troka password bootstrap, proteje secret file no kria konta tuir papél.

Dashboard:

```text
http://127.0.0.1:8000
```

### 5.4 Threshold no mode IDS-only

Durante observasaun dahuluk, desativa IPS maibé husik alerta ativu:

```toml
[ips]
enabled = false

[decision]
alert_threshold = 0.5
block_threshold = 0.7
weight_signature = 0.4
weight_ml = 0.6
```

- Threshold ki'ik liu aumenta sensitividade no false positive.
- `block_threshold` tenke boot ka hanesan `alert_threshold`.
- Ativa IPS depois whitelist, alert quality no rollback test pasa.
- Mudansa ne'ebé afeta capture/database normalmenti presiza restart.

### 5.5 Path importante

| Rekursu | Path |
|---|---|
| Konfigurasaun | `/etc/sagedral/config.toml` |
| Data | `/var/lib/sagedral-ml/` |
| Modelu | `/var/lib/sagedral-ml/models/` |
| Database | `/var/lib/sagedral-ml/sagedral.db` |
| Backup | `/var/lib/sagedral-ml/backups/` |
| Regra custom | `/var/lib/sagedral-ml/custom-rules/` |
| Secret admin | `/var/lib/sagedral-ml/.sagedral-admin-secret` |
| Secret JWT | `/var/lib/sagedral-ml/.sagedral-jwt-secret` |
| Log | `/var/log/sagedral-ml.log` no journal |
| Service | `/etc/systemd/system/sagedral-ml.service` |

---

## 6. Komandu CLI importante

Komandu ne'ebé asesu config/model/backup protejidu diretamente tenke uza
identidade service:

```bash
sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml config show
```

Komandu API hanesan alert, block no whitelist bele hala'o husi konta shell
depois `sagedral-ml login`.

### 6.1 Service no saúde

```bash
sagedral-ml health
sagedral-ml status
sudo systemctl restart sagedral-ml
sudo systemctl status sagedral-ml
sudo journalctl -u sagedral-ml -f
```

### 6.2 Konfigurasaun

```bash
sagedral-ml config show
sagedral-ml config validate
sagedral-ml config template
```

### 6.3 Alert

```bash
sagedral-ml alerts list --limit 50
```

Export CSV disponível iha dashboard no endpoint
`/api/v1/alerts/export.csv` depois login.

### 6.4 Block, unblock no whitelist

```bash
sagedral-ml block 203.0.113.20 \
  --duration 3600 \
  --reason "Scan suspeitu"

sagedral-ml unblock 203.0.113.20

sagedral-ml whitelist list
sagedral-ml whitelist add 192.168.10.0/24 --note "Rede jestaun"
sagedral-ml whitelist remove 192.168.10.0/24
```

### 6.5 Database no backup

```bash
sagedral-ml database migrate
sagedral-ml backup create
sagedral-ml backup list
```

### 6.6 Modelu

```bash
sagedral-ml model info
sagedral-ml model init
sagedral-ml model init --force
```

`model init` kria fallback se modelu trained seidauk iha. `--force` substitui
fallback/model pointer ativu; halo backup se iha modelu importante.

### 6.7 Self-test

```bash
sagedral-ml selftest capture --help
sagedral-ml selftest sniffer-status
python scripts/pcap_regression.py --self-test
python scripts/benchmark.py --iterations 10000 --minimum-fps 1000
```

---

## 7. Training modelu CICIDS2017/2018

### 7.1 Komprende rezultadu

- Metrika fallback synthetic la'ós akurásia production.
- Depois training, dashboard hatudu anomaly accuracy, anomaly F1 no
  classification accuracy husi holdout.
- Holdout random la substitui teste loron/dataset separadu.
- Training full dataset bele demora oras no konsome RAM/disku boot.

### 7.2 Prepara diretóriu

```bash
sudo install -d -o sagedral -g sagedral -m 0750 \
  /var/lib/sagedral-ml/datasets/cicids2017 \
  /var/lib/sagedral-ml/datasets/cicids2018
```

### 7.3 CICIDS2017

Download `MachineLearningCSV.zip` husi
[pájina UNB CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html), depois:

```bash
sudo apt-get install -y unzip
sudo unzip MachineLearningCSV.zip \
  -d /var/lib/sagedral-ml/datasets/cicids2017

sudo chown -R sagedral:sagedral \
  /var/lib/sagedral-ml/datasets/cicids2017
sudo find /var/lib/sagedral-ml/datasets/cicids2017 \
  -type d -exec chmod 0750 {} \;
sudo find /var/lib/sagedral-ml/datasets/cicids2017 \
  -type f -name '*.csv' -exec chmod 0640 {} \;
```

### 7.4 CSE-CIC-IDS2018

UNB publika dataset iha AWS. Instala AWS CLI no sync CSV processadu:

```bash
sudo apt-get install -y awscli

sudo -u sagedral aws s3 sync \
  --no-sign-request \
  --region us-east-1 \
  "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/" \
  /var/lib/sagedral-ml/datasets/cicids2018
```

Referénsia:
[UNB CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html).

Labele aponta `--dataset` ba bucket full ne'ebé inklui CSV log ne'ebé la'ós
CICFlowMeter ML, tanba importer deliberadamente rejeita file ho feature
coverage menus.

### 7.5 Training dataset ida

Ezemplu seguru ba VM:

```bash
sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml train \
  --dataset /var/lib/sagedral-ml/datasets/cicids2017 \
  --save-dir /var/lib/sagedral-ml/models \
  --train-test-split 0.2 \
  --max-rows-per-class 100000
```

`--max-rows-per-class 100000` limita memória ho sample determinístiku per
classe. Uza `0` deit se RAM boot no hakarak full corpus:

```bash
sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml train \
  --dataset /var/lib/sagedral-ml/datasets/cicids2017 \
  --save-dir /var/lib/sagedral-ml/models \
  --train-test-split 0.2 \
  --max-rows-per-class 0
```

### 7.6 Kombina 2017 no 2018

Tanba pasta `/var/lib/sagedral-ml/datasets` iha subpasta 2017 no 2018, pipeline
bele scan rua hotu se parent ne'e la iha CSV seluk. Konfirma uluk:

```bash
find /var/lib/sagedral-ml/datasets \
  -type f -iname '*.csv' | head
```

Depois:

```bash
sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml train \
  --dataset /var/lib/sagedral-ml/datasets \
  --save-dir /var/lib/sagedral-ml/models \
  --train-test-split 0.2 \
  --max-rows-per-class 100000
```

### 7.7 Ativa no verifika modelu

Training publica version foun atomikamente. Service ne'ebé dadaun hala'o
presiza restart atu load:

```bash
sudo systemctl restart sagedral-ml

sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml model info

sudo cat /var/lib/sagedral-ml/models/active_model.json
```

Rezultadu espera:

- `loaded: true`;
- `model_version` la iha sufixu `fallback`;
- accuracy/F1 la `null`;
- dashboard `/model` hatudu percentajen.

### 7.8 Avaliasaun separadu

`evaluate_model.py` atual espera CSV canonical ho feature runtime 28; labele
fó raw CICFlowMeter diretamente:

```bash
python3 -m sagedral_ml.scripts.evaluate_model \
  --test-data /path/test-canonical-28-features.csv \
  --model-dir /var/lib/sagedral-ml/models
```

Ba raw CICIDS, rezerva file/loron antes training no transforma ho importer
canonical ne'ebé hanesan pipeline training, depois avalia. Dokumenta
distribuisaun classe, data split no metrikas.

---

## 8. Operasaun loroloron

### 8.1 Checklist

```bash
sagedral-ml health
sagedral-ml status
sudo systemctl status sagedral-ml --no-pager
sudo journalctl -u sagedral-ml --since today
curl -fsS http://127.0.0.1:8000/healthz
curl -fsS http://127.0.0.1:8000/readyz
curl -s http://127.0.0.1:8000/metrics
sagedral-ml backup list
df -h /var/lib/sagedral-ml
```

Haree:

- capture running;
- packet queue drop no kernel drop;
- interface ne'ebé sistema hili;
- alert backlog;
- block ne'ebé expiry ona;
- model version/fallback/drift;
- database no disk size;
- SIEM/notification failure;
- HA peer sync.

### 8.2 Firewall

```bash
sudo nft list table inet sagedral
sudo iptables -S
sagedral-ml whitelist list
```

### 8.3 Log

```bash
sudo journalctl -u sagedral-ml -f
sudo journalctl -u sagedral-ml -p warning --since "1 hour ago"
sudo tail -f /var/log/sagedral-ml.log
```

---

## 9. Resposta insidente

1. Labele hamos alerta antes export CSV no audit snapshot.
2. Verifika source/destination, signature, pontu ML, GeoIP no flow.
3. Analyst marka true positive, false positive ka uncertain.
4. Verifika whitelist no gateway antes block manual.
5. Ba false positive, uza threshold/override per-rule ne'ebé estreitu.
6. Labele whitelist subnet boot sem aprovasaun.
7. Rejista tempu, uza-na'in, razaun no mudansa iha ticket insidente.

Block temporáriu:

```bash
sagedral-ml block 203.0.113.20 \
  --duration 1800 \
  --reason "Investigasaun SOC"
```

---

## 10. Backup no restore

### 10.1 Kria backup

```bash
sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml backup create \
  --output /var/lib/sagedral-ml/backups/manual-$(date +%F).tar.gz

sagedral-ml backup list
```

Backup bele inklui config, secret, database no modelu. Trata hanesan data
sensível; archive CLI iha permission `0600`.

### 10.2 Restore

Halo restore iha maintenance window:

```bash
sudo systemctl stop sagedral-ml

sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml backup restore \
  --source /path/backup.tar.gz \
  --confirm

sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml database migrate

sudo systemctl start sagedral-ml
sagedral-ml health
```

Restore rejeita archive traversal/link no kria kopia `before-restore` antes
overwrite.

---

## 11. Upgrade no rollback

### 11.1 Upgrade husi Git

```bash
cd ~/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML

sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml backup create \
  --output /var/lib/sagedral-ml/backups/pre-upgrade-$(date +%F-%H%M).tar.gz

git pull --ff-only
sudo python3 -m pip install --no-deps .

sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml database migrate

sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml config validate

sudo systemctl restart sagedral-ml
sagedral-ml health
sagedral-ml model info
```

### 11.2 Rollback

1. Stop service.
2. Instala commit/wheel anteriór.
3. Restore backup pre-upgrade.
4. Hala'o migration ne'ebé kompatível ho versaun anteriór.
5. Start no valida health/model/firewall.

Labele downgrade schema destrutivamente sem backup testadu.

---

## 12. TLS no asesu external

Bind API ba localhost:

```toml
[api]
host = "127.0.0.1"
port = 8000
```

Instala template:

```bash
sudo cp deploy/nginx-sagedral.conf /etc/nginx/sites-available/sagedral-ml
sudo ln -s /etc/nginx/sites-available/sagedral-ml \
  /etc/nginx/sites-enabled/sagedral-ml

sudo nginx -t
sudo systemctl reload nginx
```

Antes reload:

- troka hostname;
- troka path certificate/key;
- ajusta trusted proxy;
- limita management network;
- testa HTTPS no WebSocket.

---

## 13. Monitoring, database no integrasaun

### 13.1 Endpoint

```bash
curl -f http://127.0.0.1:8000/healthz
curl -f http://127.0.0.1:8000/readyz
curl http://127.0.0.1:8000/metrics
```

### 13.2 Docker monitoring stack

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f sagedral
```

Container presiza `NET_RAW`, `NET_ADMIN` no host networking atu kaptura/block.

### 13.3 Benchmark

```bash
python scripts/benchmark.py \
  --iterations 10000 \
  --minimum-fps 1000

python scripts/pcap_regression.py --self-test
```

Ba produsaun, halo soak test mínimu 24 oras ho traffic representativu. Reklame
1 Gbps presiza prova hardware/NIC/kernel alvu.

### 13.4 PostgreSQL

Instala dependénsia:

```bash
cd ~/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML
sudo python3 -m pip install ".[postgres]"
```

Konfigura connection string liu husi secret management ne'ebé organizasaun
kontrola:

```toml
[database]
backend = "postgresql"
connection_string = "postgresql+asyncpg://sagedral:password@db/sagedral"
run_migrations = true
```

Depois:

```bash
sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml database migrate

sudo systemctl restart sagedral-ml
```

Labele commit password database ba Git.

### 13.5 GeoIP

```bash
cd ~/SAGEDRAL-ML-Smart-Adaptive-Guardian-for-Detection-Response-and-Adaptive-Learning-ML
sudo python3 -m pip install ".[geoip]"
```

```toml
[geolocation]
enabled = true
db_path = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
```

Uza database MaxMind ne'ebé organizasaun iha lisensa no atualiza nia data
periodikamente.

### 13.6 SIEM, webhook, email no Telegram

```toml
[siem]
enabled = true
minimum_severity = "MEDIUM"
syslog_host = "10.20.0.30"
syslog_port = 514
syslog_protocol = "tcp"
webhook_urls = ["https://hooks.example.invalid/services/..."]
webhook_timeout_seconds = 5

[notifications]
enabled = true
minimum_severity = "HIGH"
telegram_bot_token = "SECRET"
telegram_chat_id = "CHAT-ID"
smtp_host = "smtp.example.internal"
smtp_port = 587
smtp_starttls = true
smtp_username = "sagedral"
smtp_password = "SECRET"
email_sender = "sagedral@example.internal"
email_recipients = ["soc@example.internal"]
```

Depois edita:

```bash
sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  sagedral-ml config validate

sudo systemctl restart sagedral-ml
sudo journalctl -u sagedral-ml -f
```

Webhook tenke HTTPS. Limita syslog/firewall ba SIEM host deit. Proteje token no
SMTP password.

### 13.7 Performance profile

```toml
[capture]
backend = "af_packet"
queue_maxsize = 10000

[feature_extraction]
max_active_flows = 50000

[ml]
batch_size = 32
batch_timeout_ms = 50

[performance]
detection_workers = 2
profile_enabled = false
```

Labele aumenta worker/queue sem mede CPU, RAM, latency no drop.

---

## 14. HA active-passive

Template: `deploy/keepalived-sagedral.conf`.

Rekizitu:

- `node_id` diferente;
- `shared_secret` hanesan no mínimu karakter 24;
- peer endpoint limitadu ba management IP;
- PostgreSQL shared/replicated;
- VIP, route no firewall testadu;
- certificate no model version konsistente.

Durante failover:

```bash
ip address show
ip neigh show
sudo nft list table inet sagedral
sagedral-ml health
sagedral-ml model info
```

Konfirma ARP/NDP, dashboard, capture, blocklist no peer sync.

---

## 15. Custom signature DSL

Ezemplu payload:

```json
{
  "rule_id": "CUSTOM-SSH-01",
  "name": "SSH burst",
  "description": "Koneksaun SSH badak no barak",
  "severity": "HIGH",
  "condition_expr": "flow.get('dst_port', 0) == 22 and total_fwd_packets > 30",
  "attack_type": "BruteForce"
}
```

DSL suporta operasaun númeriku, boolean, komparasaun, feature name no
`flow.get()`. Import, dunder, comprehension, lambda, assignment no function
call seluk rejeitadu.

---

## 16. Troubleshooting

### 16.1 Service falla iha `ExecStartPre`

Se journal hatudu `Permission denied`:

```bash
sudo install -d -o root -g sagedral -m 2770 /etc/sagedral
sudo chown root:sagedral /etc/sagedral/config.toml
sudo chmod 0660 /etc/sagedral/config.toml

sudo install -d -o sagedral -g sagedral -m 0750 \
  /var/lib/sagedral-ml \
  /var/lib/sagedral-ml/models \
  /var/lib/sagedral-ml/backups \
  /var/lib/sagedral-ml/custom-rules

sudo chown -R sagedral:sagedral /var/lib/sagedral-ml
sudo touch /var/log/sagedral-ml.log
sudo chown sagedral:sagedral /var/log/sagedral-ml.log
sudo chmod 0640 /var/log/sagedral-ml.log

sudo install -o root -g root -m 0644 \
  systemd/sagedral-ml.service \
  /etc/systemd/system/sagedral-ml.service

sudo systemctl daemon-reload
```

Test identidade service:

```bash
sudo -u sagedral env \
  HOME=/var/lib/sagedral-ml \
  SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
  /usr/local/bin/sagedral-ml config validate

sudo systemctl restart sagedral-ml
sudo systemctl status sagedral-ml --no-pager -l
sudo journalctl -u sagedral-ml -n 100 --no-pager -o cat
```

Se kontinua:

```bash
namei -l /etc/sagedral/config.toml
namei -l /var/lib/sagedral-ml
```

Labele troka service sai `root`; hadi'a ownership/path.

### 16.2 La kaptura pakote

```bash
ip -brief address
sudo tcpdump -ni eth0 -c 20
sagedral-ml selftest capture --help
sagedral-ml selftest sniffer-status
sudo journalctl -u sagedral-ml | grep -i capture
```

- Konfirma interface iha config.
- Konfirma interface `UP`.
- Konfirma tcpdump haree pakote.
- Ba SPAN, konfirma switch mirror direction.
- Ba VirtualBox, konfirma bridged/promiscuous policy.
- Ba AF_PACKET, konfirma kernel no capability.

### 16.3 IP administradór blokeadu

Uza console/VNC:

```bash
sudo nft list table inet sagedral
sudo nft delete element inet sagedral blocklist \
  '{ 203.0.113.10 }'
```

Troka IP ezemplu ho IP real, depois aumenta whitelist:

```bash
sagedral-ml whitelist add 203.0.113.10 \
  --note "IP administrasaun"
sudo systemctl restart sagedral-ml
```

### 16.4 Dashboard la bele asesu

```bash
sagedral-ml health
sudo ss -ltnp | grep 8000
curl -v http://127.0.0.1:8000/healthz
sudo journalctl -u sagedral-ml -n 100
```

Konfirma `api.host`, firewall, Nginx, certificate no browser URL. Ba external,
uza HTTPS reverse proxy; labele expoin API plain-text ba internet.

### 16.5 Alert falsu barak

1. Hahu ho `[ips] enabled = false`.
2. Analiza fonte no regra ne'ebé dispara.
3. Aumenta threshold gradualmente.
4. Uza per-rule override ba fonte ne'ebé loos.
5. Uza BPF filter se sensor proteje deit servisu espesífiku.
6. Train/avalia modelu ho data ne'ebé representa rede.

### 16.6 Metrika modelu `La disponível`

```bash
sagedral-ml model info
sudo cat /var/lib/sagedral-ml/models/active_model.json
sudo journalctl -u sagedral-ml | grep -i model
```

- Fallback metadata tenke fó nota synthetic.
- Modelu legacy sem metadata bele hatudu `La disponível`.
- Depois training, restart service.
- Konfirma `model_metadata.json` iha version directory ativu.

### 16.7 CLI status husu login

```bash
sagedral-ml health
sagedral-ml login
sagedral-ml status
```

Status detail presiza JWT. Endpoint health/status mínimu bele uza ba monitoring.

---

## 17. Disaster recovery

### 17.1 Node ida

1. Izola node husi inline path ka muda VIP ba passive.
2. Provision OS/Python no instala versaun aplikasaun ne'ebé hanesan.
3. Restore config, database, modelu, GeoIP no certificate.
4. Hala'o `config validate` no `database migrate`.
5. Start sem capture no testa health, login, audit no modelu.
6. Ativa capture no konfirma drop/reconcile firewall.
7. Hatama node ba inline path gradualmente.

### 17.2 Evidénsia ne'ebé tenke rai

- backup hash no data;
- application commit/version;
- database revision;
- active model version;
- config sanitized;
- firewall/blocklist snapshot;
- certificate expiry;
- test result no responsável.

---

## 18. Verifikasaun dezenvolvedór

```bash
python3 -m pytest tests/test_train_model.py \
  tests/test_ml_engine.py \
  tests/test_cli.py \
  tests/test_api.py -q

python3 -m compileall -q sagedral_ml

cd sagedral_ml/dashboard
npm ci
npm run build
```

PCAP:

```bash
python scripts/pcap_regression.py \
  --pcap /path/sample.pcap \
  --ground-truth /path/ground-truth.json \
  --minimum-precision 0.70 \
  --minimum-recall 0.85
```

---

## 19. Acceptance antes produsaun

- [ ] Config validate pasa ho identidade `sagedral`.
- [ ] Dashboard/API protejidu ho TLS.
- [ ] Secret default troka no file permission loos.
- [ ] Gateway/management/monitoring IP iha whitelist.
- [ ] Modelu trained, la fallback.
- [ ] Dataset test separadu atinji metrika aprova.
- [ ] PCAP regression pasa.
- [ ] Soak test mínimu 24 oras pasa.
- [ ] Packet/kernel drop iha limite.
- [ ] Backup restore test ona.
- [ ] Rollback test ona.
- [ ] Firewall reboot persistence test ona.
- [ ] Failover HA test ona se uza HA.
- [ ] SIEM/notification/GeoIP test ona se ativu.

---

## 20. Dezinstalasaun

> **Avizu:** operasaun ida-ne'e para servisu no hamos regra firewall SAGEDRAL.
> Installer preserve database, config no log, maibé halo backup uluk.

```bash
sudo bash scripts/uninstall.sh
```

Depois verifika:

```bash
systemctl status sagedral-ml
sudo nft list ruleset | grep -i sagedral
```

Hamos data/config manualmente mak destrutivu no la bele recovery sem backup.

---

## 21. Referénsia lalais

| Objetivu | Komandu |
|---|---|
| Saúde | `sagedral-ml health` |
| Status | `sagedral-ml status` |
| Log live | `sudo journalctl -u sagedral-ml -f` |
| Valida config | `sagedral-ml config validate` |
| Modelu | `sagedral-ml model info` |
| Alert | `sagedral-ml alerts list --limit 50` |
| Whitelist | `sagedral-ml whitelist list` |
| Backup | `sagedral-ml backup create` |
| Firewall | `sudo nft list table inet sagedral` |
| API health | `curl -f http://127.0.0.1:8000/healthz` |

Dokumentu produtu no estatutu feature iha [`prd.md`](prd.md).
