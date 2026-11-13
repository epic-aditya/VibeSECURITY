# Multi-stage hardened non-root container for VibeSec Application Security Scanner
FROM python:3.12-slim-bookworm

LABEL maintainer="VibeSec Project" \
      description="Static application security testing and dependency reachability scanner" \
      version="1.0.0"

# Set hardened environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DO_NOT_TRACK=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_VERSION_CHECK=off \
    TRIVY_NO_PROGRESS=true \
    PATH="/home/vibesec/.local/bin:${PATH}"

# Install base system dependencies and tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    nodejs \
    npm \
    tar \
    gzip \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy scanner binary
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.58.2

# Install Gitleaks scanner binary
RUN curl -sfL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks

# Create non-root user with dedicated UID/GID
RUN groupadd -g 1000 vibesec && \
    useradd -u 1000 -g vibesec -m -s /bin/bash vibesec

# Setup application directory
WORKDIR /app

# Copy dependency metadata and install Python dependencies
COPY pyproject.toml /app/
RUN pip install --no-cache-dir hatchling pip-audit bandit semgrep && \
    pip install --no-cache-dir -e .

# Copy application source code and custom rules
COPY . /app/

# Create workspaces directory with non-root ownership
RUN mkdir -p /workspace && \
    chown -R vibesec:vibesec /app /workspace

# Switch to unprivileged non-root user
USER vibesec

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

EXPOSE 8501

ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]

