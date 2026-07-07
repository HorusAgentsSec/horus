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
# When piped (curl | bash) there is no script file, so BASH_SOURCE is unset. Guard it
# under `set -u`; SCRIPT_DIR is only used by the build-from-source path (local checkout).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /tmp)"

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

# File/exec/network monitoring is handled by the kernel audit subsystem (auditd rules
# below), not app-level watch paths — that's what removes the inotify OOM.

log_level: INFO
YAML
    chmod 600 "${CONFIG_FILE}"
fi

# ── auditd setup ────────────────────────────────────────────────────────────────
# Kernel-level FIM + exec + network monitoring. Replaces inotify/procfs polling.
AUDIT_RULES_FILE="/etc/audit/rules.d/horus.rules"
if command -v auditctl &>/dev/null || apt-get install -y -qq auditd 2>/dev/null; then
    info "Configuring auditd rules at ${AUDIT_RULES_FILE} …"
    mkdir -p "$(dirname "${AUDIT_RULES_FILE}")"
    cat > "${AUDIT_RULES_FILE}" <<'RULES'
# Horus Iris audit rules; managed by installer, do not edit manually.
# Design rule: monitoring must NEVER lag the host. We keep only low-volume,
# high-signal rules and tell the kernel to drop events rather than block syscalls.

# Reset, then a large backlog with NO wait. backlog_wait_time 0 is critical: if the
# backlog fills the kernel drops audit events instead of stalling every syscall.
-D
-b 16384
--backlog_wait_time 0
-f 1

# File Integrity Monitoring; config and root home only (low volume, high value).
-w /etc -p wa -k horus_fim
-w /root -p wa -k horus_fim

# Exec from world-writable/suspicious paths only (low volume, high signal).
# We deliberately do NOT audit every execve or watch /usr/bin etc.: on a busy host
# that is thousands of events/sec and the source of system-wide lag.
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k horus_exec
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k horus_exec
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k horus_exec

# NB: system-wide -S connect auditing is intentionally omitted. Auditing every
# outbound connection floods the host (browsers, scanners) and belongs at the
# network layer, not a host agent.
RULES
    if command -v augenrules &>/dev/null; then
        augenrules --load 2>/dev/null && info "Audit rules loaded via augenrules."
    else
        auditctl -R "${AUDIT_RULES_FILE}" 2>/dev/null && info "Audit rules loaded via auditctl."
    fi
    systemctl enable --now auditd 2>/dev/null || true
else
    warn "auditd not available — file/exec/network monitoring disabled (journald still active)."
fi

# ── systemd service ───────────────────────────────────────────────────────────
# Written inline so the script works when piped (curl | bash), with no source checkout.
if command -v systemctl &>/dev/null; then
    info "Installing systemd service …"
    # Stop any running instance BEFORE swapping the unit. Without this, an upgrade (e.g. the
    # Python→Rust migration) leaves the old MainPID running under the service — daemon-reload alone
    # does NOT restart it — so the old process keeps running (and, in the Python case, leaking
    # memory) indefinitely while the new binary never starts.
    was_active=no
    if systemctl is-active --quiet horus-iris; then
        was_active=yes
    fi
    systemctl stop horus-iris 2>/dev/null || true
    cat > "${SERVICE_FILE}" <<'UNIT'
[Unit]
Description=Horus Iris Security Agent
Documentation=https://docs.horus.security/iris
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/horus-iris
Restart=always
RestartSec=10
User=root

EnvironmentFile=-/etc/horus/iris.env

StandardOutput=journal
StandardError=journal
SyslogIdentifier=horus-iris

NoNewPrivileges=yes
ProtectSystem=no
PrivateTmp=no

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    # If it was running, restart it now so the freshly installed binary actually takes over
    # (instead of waiting for a manual command while the old process lingers).
    if [ "${was_active}" = yes ]; then
        systemctl restart horus-iris && info "Service restarted on the new binary."
    fi
    info "Service installed."
else
    warn "systemctl not found; run manually: horus-iris"
fi

# ── clean up the legacy Python install ─────────────────────────────────────────
# Iris used to ship as a Python daemon under /opt/horus/iris (the one with the memory leak that
# motivated this Rust rewrite). Once the Rust service is in place, remove it so it can't be
# resurrected or confused with the current agent.
if [ -d /opt/horus/iris ]; then
    info "Removing legacy Python install at /opt/horus/iris …"
    rm -rf /opt/horus/iris
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
