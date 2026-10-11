# Pinned slim base image. Runs as a non-root user.
FROM python:3.12.8-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SENTINEL_LOG_DIR=/var/log/sentinel

WORKDIR /app

RUN groupadd --system sentinel \
    && useradd --system --gid sentinel --home-dir /app --shell /usr/sbin/nologin sentinel

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel_fixed ./sentinel_fixed
# The compose file mounts the named volume sentinel-logs at SENTINEL_LOG_DIR.
# Docker seeds an empty named volume with the image directory's ownership, so
# the directory must exist here and be owned by the non-root user, or every
# request log write fails with PermissionError.
RUN mkdir -p /var/log/sentinel && chown sentinel:sentinel /var/log/sentinel

USER sentinel

EXPOSE 5002

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5002/health', timeout=2).status == 200 else 1)"

CMD ["flask", "--app", "sentinel_fixed:create_app", "run", "--host", "0.0.0.0", "--port", "5002"]
