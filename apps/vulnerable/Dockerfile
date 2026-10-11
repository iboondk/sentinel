# INTENTIONALLY INSECURE demo image: unpinned base, runs as root, debug on.
# It exists only so scanners have something to find. Never deploy it.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY sentinel_vuln ./sentinel_vuln

EXPOSE 5001
CMD ["flask", "--app", "sentinel_vuln:create_app", "run", "--host", "0.0.0.0", "--port", "5001"]
