FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IDE_SCANNER_DATA_DIR=/data

ARG GITLEAKS_VERSION=8.30.1
ARG OSV_SCANNER_VERSION=2.6.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl nodejs \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o /tmp/gitleaks.tar.gz \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" -o /tmp/gitleaks_checksums.txt \
    && grep "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" /tmp/gitleaks_checksums.txt | sed "s#  gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz#  /tmp/gitleaks.tar.gz#" | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" -o /tmp/osv-scanner \
    && curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_SHA256SUMS" -o /tmp/osv-scanner_checksums.txt \
    && grep "osv-scanner_linux_amd64" /tmp/osv-scanner_checksums.txt | sed "s#  osv-scanner_linux_amd64#  /tmp/osv-scanner#" | sha256sum -c - \
    && install -m 0755 /tmp/osv-scanner /usr/local/bin/osv-scanner \
    && rm -f /tmp/gitleaks.tar.gz /tmp/gitleaks_checksums.txt /tmp/osv-scanner_checksums.txt \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY rules ./rules
RUN python -m pip install --no-cache-dir .

VOLUME ["/data"]
EXPOSE 8787
CMD ["ide-scanner-service", "--host", "0.0.0.0", "--port", "8787", "--data-dir", "/data"]
