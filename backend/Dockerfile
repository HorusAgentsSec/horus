FROM python:3.12-slim

# Scanners the pipeline shells out to. Without these every scan runs, silently
# skips both tools ("binary not found") and reports zero findings:
#   - nmap: the Debian package bundles the NSE scripts, incl. the `vuln` category
#   - nuclei: ProjectDiscovery's prebuilt binary + its templates (pre-fetched so the
#     first scan doesn't pay the download and works even if the CDN is flaky)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
        wget \
        unzip \
    && rm -rf /var/lib/apt/lists/*

ARG NUCLEI_VERSION=3.8.0
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && nuclei -update-templates -silent || true

# Build context is the project root (see docker-compose.yml) so that `backend`
# stays an importable package — the codebase uses absolute `from backend.…` imports.
WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend ./backend
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
