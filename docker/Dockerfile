# syntax=docker/dockerfile:1.6
FROM python:3.12-slim-bookworm AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# libmagic1 is required by python-magic at runtime
# tini gives us proper PID 1 signal handling
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libmagic1 \
        tini \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY pyproject.toml /app/pyproject.toml
COPY README.md /app/README.md
COPY LICENSE /app/LICENSE
COPY src /app/src

RUN pip install --no-cache-dir --no-deps .

RUN groupadd --system --gid 1000 vulcan \
 && useradd  --system --uid 1000 --gid vulcan --home /app --shell /usr/sbin/nologin vulcan \
 && chown -R vulcan:vulcan /app

USER vulcan

EXPOSE 5000

ENV VULCAN_LOG_LEVEL=INFO \
    VULCAN_JSON_LOGS=true \
    VULCAN_MAX_CONTENT_LENGTH=1048576 \
    GUNICORN_WORKERS=2 \
    GUNICORN_THREADS=4 \
    GUNICORN_TIMEOUT=30

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys;\
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3).status==200 else 1)" \
  || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "exec gunicorn vulcan.wsgi:app \
        --bind 0.0.0.0:5000 \
        --workers ${GUNICORN_WORKERS} \
        --threads ${GUNICORN_THREADS} \
        --timeout ${GUNICORN_TIMEOUT} \
        --access-logfile - \
        --error-logfile -"]
