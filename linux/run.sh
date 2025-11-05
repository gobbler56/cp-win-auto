#!/bin/bash
#
# Linux CyberPatriot Automation Launcher
#
# This script runs all Linux hardening modules in sequence.
# Modules: README Parser, Service Auditing (extensible)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
CONFIG_FILE="$SCRIPT_DIR/config.conf"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info() {
    echo -e "${CYAN}[INFO]${NC} $*"
}

log_ok() {
    echo -e "${GREEN}[OK]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

banner() {
    echo -e "${BOLD}${CYAN}"
    echo "========================================"
    echo "  Linux CyberPatriot Automation"
    echo "========================================"
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_env() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Config file not found at $CONFIG_FILE"
        echo ""
        echo "Create it with:"
        echo "  cp $CONFIG_FILE.example $CONFIG_FILE"
        echo "  # Edit and add your OPENROUTER_API_KEY"
        exit 1
    fi

    # Source config to check API key
    source "$CONFIG_FILE"

    if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
        log_error "OPENROUTER_API_KEY not set in $CONFIG_FILE"
        echo ""
        echo "Edit $CONFIG_FILE and set:"
        echo "  OPENROUTER_API_KEY=\"sk-or-v1-...\""
        exit 1
    fi
}

main() {
    banner

    log_info "Starting Linux hardening automation..."

    check_root
    check_env

    log_ok "Pre-flight checks passed"
    echo ""

    # Module 0: README Parser (must run first)
    if [[ -x "$MODULES_DIR/readme_parser.sh" ]]; then
        log_info "Running README Parser Module..."
        echo ""

        if "$MODULES_DIR/readme_parser.sh"; then
            log_ok "README Parser Module completed"
        else
            log_error "README Parser Module failed"
            exit 1
        fi
    else
        log_error "README Parser Module not found or not executable"
        exit 1
    fi

    echo ""

    # Module 1: Service Auditing
    if [[ -x "$MODULES_DIR/service_auditing.sh" ]]; then
        log_info "Running Service Auditing Module..."
        echo ""

        if "$MODULES_DIR/service_auditing.sh"; then
            log_ok "Service Auditing Module completed"
        else
            log_error "Service Auditing Module failed"
            exit 1
        fi
    else
        log_error "Service Auditing Module not found or not executable"
        exit 1
    fi

    echo ""
    echo -e "${BOLD}${GREEN}"
    echo "========================================"
    echo "  All modules completed successfully!"
    echo "========================================"
    echo -e "${NC}"
}

main "$@"
