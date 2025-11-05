#!/bin/bash
#
# Linux OS Updates Module for CyberPatriot
#
# This script:
# 1. Updates package lists
# 2. Installs and configures unattended-upgrades for automatic security updates
# 3. Enables automatic upgrade timers
# 4. Performs full system upgrade (including kernel updates)
# 5. Removes unnecessary packages
#
# Requirements:
#   - Root/sudo privileges
#   - Debian/Ubuntu-based system (apt)
#
# NOTE: This script does NOT reboot the system after kernel upgrades.
#       If a kernel upgrade is performed, a manual reboot is required.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX_DIR="$(dirname "$SCRIPT_DIR")"
LOG_PREFIX="[OSUpdates]"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${CYAN}${LOG_PREFIX} [INFO]${NC} $*"
}

log_ok() {
    echo -e "${GREEN}${LOG_PREFIX} [OK]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}${LOG_PREFIX} [WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}${LOG_PREFIX} [ERROR]${NC} $*"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check if this is a Debian/Ubuntu system
check_system() {
    if ! command -v apt-get &> /dev/null; then
        log_error "This script requires apt-get (Debian/Ubuntu-based system)"
        exit 1
    fi
    log_info "Detected apt-based system"
}

# Update package lists
update_package_lists() {
    log_info "Updating package lists..."

    if apt-get update -qq 2>&1; then
        log_ok "Package lists updated successfully"
        return 0
    else
        log_error "Failed to update package lists"
        return 1
    fi
}

# Install unattended-upgrades
install_unattended_upgrades() {
    log_info "Installing unattended-upgrades..."

    # Check if already installed
    if dpkg -l | grep -q "^ii  unattended-upgrades "; then
        log_info "unattended-upgrades is already installed"
        return 0
    fi

    if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades 2>&1 | grep -v "^Reading" | grep -v "^Building"; then
        log_ok "Installed unattended-upgrades"
        return 0
    else
        log_error "Failed to install unattended-upgrades"
        return 1
    fi
}

# Configure unattended-upgrades
configure_unattended_upgrades() {
    log_info "Configuring unattended-upgrades..."

    # Non-interactive configuration
    if DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive unattended-upgrades 2>&1 | grep -v "^Reading" | grep -v "^Building"; then
        log_ok "Configured unattended-upgrades"
        return 0
    else
        log_warn "Failed to configure unattended-upgrades (may already be configured)"
        return 0  # Non-fatal
    fi
}

# Enable automatic upgrade timers
enable_upgrade_timers() {
    log_info "Enabling automatic upgrade timers..."

    local timers=(
        "apt-daily.timer"
        "apt-daily-upgrade.timer"
    )

    local enabled_count=0

    for timer in "${timers[@]}"; do
        if systemctl is-enabled "$timer" &>/dev/null; then
            log_info "$timer is already enabled"
        else
            if systemctl enable "$timer" &>/dev/null 2>&1; then
                log_ok "Enabled $timer"
                ((enabled_count++))
            else
                log_warn "Failed to enable $timer (may not exist on this system)"
            fi
        fi

        # Start the timer if not running
        if ! systemctl is-active "$timer" &>/dev/null; then
            if systemctl start "$timer" &>/dev/null 2>&1; then
                log_ok "Started $timer"
            else
                log_warn "Failed to start $timer"
            fi
        fi
    done

    if [[ $enabled_count -gt 0 ]]; then
        log_ok "Enabled $enabled_count timer(s)"
    else
        log_info "All timers already configured"
    fi
}

# Perform full system upgrade
perform_full_upgrade() {
    log_info "Performing full system upgrade (this may take several minutes)..."
    log_warn "This includes kernel updates if available"

    # Use --with-new-pkgs to allow installing new dependencies
    # Use -y to auto-accept
    # Capture output but show errors
    if DEBIAN_FRONTEND=noninteractive apt-get -y --with-new-pkgs full-upgrade 2>&1 | \
        tee /tmp/apt-upgrade.log | \
        grep -v "^Reading" | \
        grep -v "^Building" | \
        grep -v "^Unpacking" | \
        grep -v "^Preparing" | \
        grep -v "^Selecting" | \
        grep -v "^Setting up" | \
        grep -v "^Processing" | \
        grep -v "^(Reading database" | \
        grep -E "(Upgrading|Installing|Removing|upgraded|newly installed|to remove|The following)"; then
        :
    fi

    # Check if upgrade was successful
    if [[ $? -eq 0 ]] || grep -q "0 upgraded, 0 newly installed" /tmp/apt-upgrade.log; then
        log_ok "System upgrade completed successfully"

        # Check if kernel was upgraded
        if grep -qE "(linux-image|linux-headers|linux-modules)" /tmp/apt-upgrade.log; then
            echo ""
            echo -e "${BOLD}${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${BOLD}${YELLOW}║                                                            ║${NC}"
            echo -e "${BOLD}${YELLOW}║  ⚠️  KERNEL UPDATE DETECTED - REBOOT REQUIRED/ADVISED  ⚠️   ║${NC}"
            echo -e "${BOLD}${YELLOW}║                                                            ║${NC}"
            echo -e "${BOLD}${YELLOW}║  A kernel update has been installed. To complete the      ║${NC}"
            echo -e "${BOLD}${YELLOW}║  update and ensure system security, please reboot the     ║${NC}"
            echo -e "${BOLD}${YELLOW}║  system at your earliest convenience.                     ║${NC}"
            echo -e "${BOLD}${YELLOW}║                                                            ║${NC}"
            echo -e "${BOLD}${YELLOW}║  Command: sudo reboot                                      ║${NC}"
            echo -e "${BOLD}${YELLOW}║                                                            ║${NC}"
            echo -e "${BOLD}${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
            echo ""
        fi

        rm -f /tmp/apt-upgrade.log
        return 0
    else
        log_error "System upgrade encountered errors"
        rm -f /tmp/apt-upgrade.log
        return 1
    fi
}

# Remove unnecessary packages
autoremove_packages() {
    log_info "Removing unnecessary packages..."

    if DEBIAN_FRONTEND=noninteractive apt-get -y autoremove --purge 2>&1 | \
        grep -v "^Reading" | \
        grep -v "^Building" | \
        grep -E "(Removing|removed|The following)"; then
        :
    fi

    if [[ $? -eq 0 ]]; then
        log_ok "Unnecessary packages removed"
        return 0
    else
        log_warn "Autoremove completed with warnings"
        return 0  # Non-fatal
    fi
}

# Main execution
main() {
    log_info "Linux OS Updates Module starting..."
    echo ""

    # Pre-flight checks
    check_root
    check_system

    echo ""

    # Step 1: Update package lists
    if ! update_package_lists; then
        log_error "Failed to update package lists, cannot proceed"
        exit 1
    fi

    echo ""

    # Step 2: Install unattended-upgrades
    install_unattended_upgrades

    echo ""

    # Step 3: Configure unattended-upgrades
    configure_unattended_upgrades

    echo ""

    # Step 4: Enable automatic upgrade timers
    enable_upgrade_timers

    echo ""

    # Step 5: Perform full system upgrade
    if ! perform_full_upgrade; then
        log_warn "System upgrade had errors, but continuing..."
    fi

    echo ""

    # Step 6: Remove unnecessary packages
    autoremove_packages

    echo ""
    log_ok "OS Updates Module completed successfully"
}

# Run main function
main "$@"
