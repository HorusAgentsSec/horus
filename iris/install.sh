#!/usr/bin/env bash
# Horus Iris installer
# Usage: sudo bash install.sh
# Env vars: HORUS_URL, HORUS_API_KEY, HORUS_AGENT_ID (optional — written to config)
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ "$(uname -s)" == "Linux" ]] || die "Horus Iris only supports Linux."
[[ "$(id -u)" -eq 0 ]]         || die "This installer must be run as root (use sudo)."

INSTALL_DIR="/opt/horus/iris"
CONFIG_DIR="/etc/horus"
CONFIG_FILE="${CONFIG_DIR}/iris.yaml"
SERVICE_FILE="/etc/systemd/system/horus-iris.service"
QUEUE_DIR="/var/lib/horus/iris"
VENV="${INSTALL_DIR}/.venv"

# ── Python ────────────────────────────────────────────────────────────────────
info "Checking Python 3…"
if ! command -v python3 &>/dev/null; then
    info "python3 not found — attempting install via apt…"
    apt-get update -qq && apt-get install -y -qq python3 python3-venv \
        || die "Could not install python3. Please install it manually."
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(sys.version_info.major * 10 + sys.version_info.minor)')
[[ "$PYTHON_VERSION" -ge 39 ]] || die "Python 3.9+ is required (found $(python3 --version))."
info "Python OK: $(python3 --version)"

# ── Copy / download source ────────────────────────────────────────────────────
info "Installing Horus Iris to ${INSTALL_DIR}…"
mkdir -p "${INSTALL_DIR}"
if [[ -n "${HORUS_URL:-}" ]]; then
    info "Downloading package from ${HORUS_URL}/api/iris/package…"
    curl -sSL "${HORUS_URL}/api/iris/package" | tar -xz -C "${INSTALL_DIR}" --strip-components=1 \
        || die "Failed to download Iris package from ${HORUS_URL}. Is the server reachable?"
else
    # Local install: BASH_SOURCE is only valid when not piped from curl
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cp -r "${SCRIPT_DIR}/." "${INSTALL_DIR}/"
fi
chmod -R 750 "${INSTALL_DIR}"

# ── Virtualenv + dependencies ─────────────────────────────────────────────────
info "Creating Python virtual environment…"
python3 -m venv "${VENV}" || die "Failed to create virtualenv. Try: apt install python3-venv"
info "Installing Python dependencies…"
"${VENV}/bin/pip" install --quiet --upgrade pip psutil watchdog pyyaml requests \
    || die "pip install failed. Check your network connection."

# ── Queue directory ───────────────────────────────────────────────────────────
mkdir -p "${QUEUE_DIR}"
chmod 700 "${QUEUE_DIR}"

# ── Config ────────────────────────────────────────────────────────────────────
mkdir -p "${CONFIG_DIR}"

if [[ -f "${CONFIG_FILE}" && -z "${HORUS_API_KEY:-}" && -z "${HORUS_AGENT_ID:-}" ]]; then
    warn "Config already exists at ${CONFIG_FILE} — skipping creation."
else
    info "Writing config at ${CONFIG_FILE}…"
    cat > "${CONFIG_FILE}" <<YAML
# Horus Iris configuration
# Edit this file then restart the service: systemctl restart horus-iris

server_url: "${HORUS_URL:-https://YOUR_HORUS_SERVER_URL}"
api_key: "${HORUS_API_KEY:-irs_REPLACE_WITH_YOUR_API_KEY}"
agent_id: "${HORUS_AGENT_ID:-REPLACE_WITH_AGENT_UUID}"

interval_seconds: 30

watch_paths:
  - /etc
  - /bin
  - /sbin
  - /usr/bin
  - /usr/sbin
  - /root

ignore_patterns:
  - "*.log"
  - "*.tmp"
  - ".git/*"

log_level: INFO
YAML
    chmod 600 "${CONFIG_FILE}"
fi

# ── systemd service ───────────────────────────────────────────────────────────
if command -v systemctl &>/dev/null; then
    info "Installing systemd service…"
    cp "${INSTALL_DIR}/horus-iris.service" "${SERVICE_FILE}"

    # Patch paths to match install location and venv
    # WorkingDirectory must be the PARENT of the iris package dir so `python3 -m iris` resolves
    sed -i "s|WorkingDirectory=.*|WorkingDirectory=$(dirname "${INSTALL_DIR}")|g" "${SERVICE_FILE}"
    sed -i "s|ExecStart=.*|ExecStart=${VENV}/bin/python3 -m iris|g" "${SERVICE_FILE}"

    systemctl daemon-reload
    info "Systemd service installed."
else
    warn "systemctl not found — skipping service installation."
    warn "To run Iris manually: cd ${INSTALL_DIR} && python3 -m iris"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Horus Iris installed successfully!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""

if grep -q "REPLACE_WITH" "${CONFIG_FILE}" 2>/dev/null; then
    echo -e "  ${YELLOW}ACTION REQUIRED:${NC}"
    echo "  Edit ${CONFIG_FILE} and set:"
    echo "    server_url, api_key, agent_id"
    echo ""
fi

echo "  Then enable and start the agent:"
echo ""
echo "    systemctl enable --now horus-iris"
echo ""
echo "  View logs:"
echo ""
echo "    journalctl -u horus-iris -f"
echo ""
