FROM python:3.12-slim AS base

LABEL maintainer="DALI Security <soc@dalisec.io>"
LABEL description="Fray — AI-Powered WAF Security Testing Platform"
LABEL org.opencontainers.image.source="https://github.com/dalisecurity/fray"
LABEL org.opencontainers.image.documentation="https://github.com/dalisecurity/fray"
LABEL org.opencontainers.image.licenses="MIT"

# Avoid Python writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install from PyPI (production image)
RUN pip install --no-cache-dir fray

# Create directories for output, session data, and templates
RUN mkdir -p /app/reports /app/templates /root/.fray

# Healthcheck: verify fray is installed and responsive
HEALTHCHECK --interval=60s --timeout=5s \
    CMD fray version || exit 1

ENTRYPOINT ["fray"]
CMD ["--help"]

# ── Development image (includes source) ────────────────────────────
FROM base AS dev

# Copy source and install in editable mode
COPY . /app/src
RUN pip install --no-cache-dir -e /app/src

# Include built-in templates for business logic testing
COPY templates/ /app/templates/

WORKDIR /app/src

# ── CI image (includes test dependencies) ──────────────────────────
FROM dev AS ci

RUN pip install --no-cache-dir pytest
CMD ["python", "-m", "pytest", "tests/", "-v"]
