#!/usr/bin/env bash
# Horus Iris uninstaller
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "Only Linux is supported."
[[ "$(id -u)" -eq 0 ]]         || die "Run as root (sudo)."

info "Stopping and disabling horus-iris service…"
systemctl stop horus-iris 2>/dev/null   || warn "Service was not running."
systemctl disable horus-iris 2>/dev/null || true
rm -f /etc/systemd/system/horus-iris.service
systemctl daemon-reload

info "Removing files…"
rm -rf /opt/horus/iris
rm -f  /etc/horus/iris.yaml
rm -rf /var/lib/horus/iris

echo ""
echo -e "${GREEN}Horus Iris uninstalled.${NC}"
echo "  Config backup (if any): /etc/horus/ directory may still exist."
echo "  To also remove it: rm -rf /etc/horus"
echo ""
