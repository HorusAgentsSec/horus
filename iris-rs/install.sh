#!/usr/bin/env bash
# Horus Iris (Rust) installer
# Usage: sudo bash install.sh
# Env vars: HORUS_URL, HORUS_API_KEY, HORUS_AGENT_ID (optional — written to config)
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "Only Linux is supported."
[[ "$(id -u)" -eq 0 ]]         || die "Run as root (sudo)."

BINARY="/usr/local/bin/horus-iris"
CONFIG_DIR="/etc/horus"
CONFIG_FILE="${CONFIG_DIR}/iris.yaml"
SERVICE_FILE="/etc/systemd/system/horus-iris.service"
QUEUE_DIR="/var/lib/horus/iris"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Build or download binary ──────────────────────────────────────────────────
if [[ -n "${HORUS_URL:-}" ]]; then
    info "Downloading binary from ${HORUS_URL}/api/iris/binary …"
    curl -sSL "${HORUS_URL}/api/iris/binary" -o "${BINARY}" \
        || die "Download failed. Is the server reachable?"
else
    info "Building horus-iris (requires Rust toolchain) …"
    BUILD_USER="${SUDO_USER:-$(logname 2>/dev/null || echo $USER)}"
    CARGO_BIN="/home/${BUILD_USER}/.cargo/bin/cargo"
    [[ -x "$CARGO_BIN" ]] || CARGO_BIN="$(su - "$BUILD_USER" -c 'command -v cargo' 2>/dev/null)" \
        || die "cargo not found for user ${BUILD_USER}. Install Rust: https://rustup.rs"
    pushd "${SCRIPT_DIR}" > /dev/null
    su - "$BUILD_USER" -c "cd '${SCRIPT_DIR}' && '${CARGO_BIN}' build --release" 2>&1 | tail -5
    cp target/release/horus-iris "${BINARY}"
    popd > /dev/null
fi

chmod 755 "${BINARY}"
info "Binary installed to ${BINARY}"

# ── Queue directory ───────────────────────────────────────────────────────────
mkdir -p "${QUEUE_DIR}"
chmod 700 "${QUEUE_DIR}"

# ── Config ────────────────────────────────────────────────────────────────────
mkdir -p "${CONFIG_DIR}"
if [[ -f "${CONFIG_FILE}" ]]; then
    warn "Config already exists at ${CONFIG_FILE} — skipping."
else
    info "Creating config at ${CONFIG_FILE} …"
    cat > "${CONFIG_FILE}" <<YAML
# Horus Iris configuration
# Edit this file then restart the service: systemctl restart horus-iris

server_url: "${HORUS_URL:-https://YOUR_HORUS_SERVER_URL}"
api_key: "${HORUS_API_KEY:-irs_REPLACE_WITH_YOUR_API_KEY}"
agent_id: "${HORUS_AGENT_ID:-REPLACE_WITH_AGENT_UUID}"

interval_seconds: 30

# System-integrity paths only. Do NOT add /home recursively: it exhausts inotify
# watches (OOM) and floods with noise. Add specific files instead, e.g.
# /home/youruser/.ssh/authorized_keys
watch_paths:
  - /etc
  - /bin
  - /sbin
  - /usr/bin
  - /usr/sbin
  - /boot

ignore_patterns:
  - "*.log"
  - "*.tmp"
  - "*.swp"
  - "*.swx"
  - "*~"
  - "*.db-wal"
  - "*.db-shm"
  - "*.db-journal"
  - "*-journal"
  - "*.pyc"
  - ".git/*"
  - "__pycache__/*"
  - "*.cache"

log_level: INFO
YAML
    chmod 600 "${CONFIG_FILE}"
fi

# ── systemd service ───────────────────────────────────────────────────────────
if command -v systemctl &>/dev/null; then
    info "Installing systemd service …"
    cp "${SCRIPT_DIR}/horus-iris.service" "${SERVICE_FILE}"
    systemctl daemon-reload
    info "Service installed."
else
    warn "systemctl not found — run manually: horus-iris"
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Horus Iris (Rust) installed successfully!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
if grep -q "REPLACE_WITH" "${CONFIG_FILE}" 2>/dev/null; then
    echo -e "  ${YELLOW}ACTION REQUIRED:${NC} Edit ${CONFIG_FILE} and set server_url, api_key, agent_id"
    echo ""
fi
echo "  systemctl enable --now horus-iris"
echo "  journalctl -u horus-iris -f"
echo ""
