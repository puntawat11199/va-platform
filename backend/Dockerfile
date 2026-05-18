# Dockerfile — VA Platform FastAPI backend
# Multi-stage build: deps layer cached separately from app code for fast rebuilds.

# ---------------------------------------------------------------------------
# Stage 1: dependency installation
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS deps

WORKDIR /install

# Install build tools needed by psycopg2-binary and cryptography packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install/packages -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: runtime image
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

WORKDIR /app

# Runtime system deps only (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from deps stage
COPY --from=deps /install/packages /usr/local

# Copy application source
COPY . .

# Create non-root user for security
RUN addgroup --system va && adduser --system --ingroup va va \
    && mkdir -p /app/reports \
    && chown -R va:va /app

USER va

# Expose FastAPI port
EXPOSE 8000

# Health check mirrors the /health endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start uvicorn with hot-reload disabled in production;
# override CMD in docker-compose for local dev with --reload
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
