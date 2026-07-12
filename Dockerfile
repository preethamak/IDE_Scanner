FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IDE_SCANNER_DATA_DIR=/data

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY rules ./rules
RUN python -m pip install --no-cache-dir .

VOLUME ["/data"]
EXPOSE 8787
CMD ["ide-scanner-service", "--host", "0.0.0.0", "--port", "8787", "--data-dir", "/data"]
