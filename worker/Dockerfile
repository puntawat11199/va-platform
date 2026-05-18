# Dockerfile — VA Platform Celery worker
# Multi-stage build mirrors the backend Dockerfile for consistency.
# Runs the Celery worker process (not a web server).

# ---------------------------------------------------------------------------
# Stage 1: dependency installation
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS deps

WORKDIR /install

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Reuse the backend requirements — worker shares the same dependency set
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install/packages -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: copy nuclei binary from the official image
# ---------------------------------------------------------------------------
FROM projectdiscovery/nuclei:latest AS nuclei-src

# ---------------------------------------------------------------------------
# Stage 3: runtime image
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    ca-certificates \
    && curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz" \
       | tar xz --strip-components=1 -C /usr/local/bin docker/docker \
    && chmod +x /usr/local/bin/docker \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from deps stage
COPY --from=deps /install/packages /usr/local

# Copy nuclei binary from official image
COPY --from=nuclei-src /usr/local/bin/nuclei /usr/local/bin/nuclei

# Copy worker source
COPY worker/ .

# Note: scanner/ scripts are mounted at runtime via docker-compose volume
# (./scanner:/app/scanner) — no COPY needed here.

# Create non-root user with a real home directory so nuclei can write its config
RUN addgroup --system va \
    && adduser --system --ingroup va --home /home/va --shell /bin/sh va \
    && mkdir -p /reports /home/va/nuclei-templates /home/va/.config/nuclei /home/va/.cache/nuclei \
    && chown -R va:va /app /reports /home/va \
    # Add va to the docker group (GID 999) so it can use the mounted Docker socket.
    # GID 999 is conventional for Docker on Linux; Docker Desktop on Windows uses a proxy
    # so the exact GID is less critical, but we set it for Linux host compatibility.
    && groupadd -g 999 docker-host 2>/dev/null || true \
    && usermod -aG docker-host va

USER va

ENV HOME=/home/va

# Celery workers have no exposed port — they consume from the Redis queue
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD celery -A celery_app.celery_app inspect ping --timeout 5 || exit 1

# Start the worker consuming from the 'scans' queue
CMD ["celery", "-A", "celery_app.celery_app", "worker", \
     "--loglevel=info", "--queues=scans", "--hostname=va-worker@%h"]
