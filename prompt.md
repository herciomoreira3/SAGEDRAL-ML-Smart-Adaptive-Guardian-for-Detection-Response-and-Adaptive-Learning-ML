buatkan saya prd.md untuk pengembangan sistem saya yang nantinya outputnya akan jadi sebuah tools "sagedral-ml" sistem tools ini adalah tools NIDPS system Machine Learning System ✅ FULL FINAL STACK + INTEGRASI IPS

(Sudah locked, tidak diubah lagi)

Final Architecture (Complete dengan IPS)

Network Traffic 

    ↓ (Promiscuous Mode)

[Scapy Capture] → Real-time packet sniffing

    ↓

[Feature Extraction] → Flow features (duration, bytes, flags, dll)

    ↓

[Hybrid Detection]

   ├── Signature Rules (simple Python rules)

   └── LightGBM ML Model (Anomaly + Classification)

    ↓

[Decision Engine] → Score > threshold = ALERT + IPS ACTION

    ↓

[Response (IPS)]

   ├── Block IP (iptables / nftables)

   ├── Drop Packet (Scapy advanced)

   └── Log + Notify

    ↓

[FastAPI Backend + WebSocket] → Kirim ke React Dashboard

    ↓

[React Dashboard] → Monitoring, Alert, Manual Block, Config

Final Tools Stack (Locked)

Layer

Tool Final

Alasan

Capture

Scapy

Paling ringan untuk Core i3

Feature Extraction

Custom Python (Scapy + dpkt)

Kontrol penuh, low RAM

ML Model

LightGBM

Cepat & hemat resource

Signature

Simple Python rule-based

Hybrid dengan ML

Backend

FastAPI

Async, WebSocket, ringan

Queue

queue.Queue + Thread

Tidak perlu Redis dulu

IPS Action

nftables (preferred) atau iptables

Native, cepat block

Database

SQLite

Ringan

Dashboard

React + Vite + Tailwind + Recharts

Kamu buat sendiri

Real-time

WebSocket (FastAPI)

Efisien

yang di mana untuk output project ini akan jadi sebuah tools bernama sagedral-ml yang bisa di install di sistem linux lain oleh buatkan prd.md nya lebih detail sedetail detail mungkin agar memunkinkan untuk ai agen murah maupun junior developer bisa membuat nya 
