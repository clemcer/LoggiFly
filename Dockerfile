ARG PYTHON_VERSION=3.13

# --- Build Stage ---
FROM python:${PYTHON_VERSION}-slim-trixie AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

# --- Final Stage: distroless ---
FROM gcr.io/distroless/python3-debian13

WORKDIR /app
# USER 1000:1000

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/usr/local/lib/python3.13/site-packages

COPY --from=builder /install /usr/local

LABEL org.opencontainers.image.source="https://github.com/clemcer/loggifly"

COPY app/ .

ENTRYPOINT ["python", "app.py"]
