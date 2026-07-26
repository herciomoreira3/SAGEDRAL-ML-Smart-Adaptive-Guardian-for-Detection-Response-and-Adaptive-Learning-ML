# syntax=docker/dockerfile:1
FROM node:18-bookworm-slim AS dashboard
WORKDIR /src/sagedral_ml/dashboard
COPY sagedral_ml/dashboard/package*.json ./
RUN npm ci
COPY sagedral_ml/dashboard/ ./
RUN npm run build

FROM python:3.8.10-slim-buster AS python-builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
RUN sed -i 's|deb.debian.org/debian|archive.debian.org/debian|g; s|security.debian.org/debian-security|archive.debian.org/debian-security|g; /buster-updates/d' /etc/apt/sources.list && \
    apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y --no-install-recommends \
    build-essential libgomp1 libpcap-dev && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md ./
COPY sagedral_ml ./sagedral_ml
COPY --from=dashboard /src/sagedral_ml/static ./sagedral_ml/static
RUN python -m pip install --upgrade pip setuptools wheel && \
    python -m pip wheel --wheel-dir /wheels .

FROM python:3.8.10-slim-buster
ENV PYTHONUNBUFFERED=1 \
    HOME=/var/lib/sagedral-ml \
    SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml \
    SAGEDRAL_GENERAL_DATA_DIR=/var/lib/sagedral-ml
RUN sed -i 's|deb.debian.org/debian|archive.debian.org/debian|g; s|security.debian.org/debian-security|archive.debian.org/debian-security|g; /buster-updates/d' /etc/apt/sources.list && \
    apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y --no-install-recommends \
    libgomp1 libpcap0.8 nftables iptables iproute2 tini curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --home-dir /var/lib/sagedral-ml --create-home sagedral
COPY --from=python-builder /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/* && rm -rf /wheels && \
    mkdir -p /etc/sagedral /var/lib/sagedral-ml && \
    sagedral-ml config template > /etc/sagedral/config.toml && \
    chown -R sagedral:sagedral /etc/sagedral /var/lib/sagedral-ml && \
    chmod 0660 /etc/sagedral/config.toml
USER sagedral
WORKDIR /var/lib/sagedral-ml
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sagedral-ml", "start", "--no-daemon"]
