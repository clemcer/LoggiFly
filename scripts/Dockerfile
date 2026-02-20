ARG PYTHON_VERSION=3.11.4
FROM python:${PYTHON_VERSION}-slim AS base

WORKDIR /app

COPY requirements.txt .

LABEL org.opencontainers.image.source="https://github.com/clemcer/loggifly"

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .
COPY scripts/v2_migration/*.py .

ENTRYPOINT ["python", "convert.py"]