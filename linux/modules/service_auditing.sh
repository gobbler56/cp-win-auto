#!/bin/bash
#
# Linux Service Auditing Module for CyberPatriot
#
# This script:
# 1. Reads parsed README data (critical services) from shared data directory
# 2. Installs and enables essential security services (hardcoded)
# 3. Disables/stops known risky services (hardcoded, excluding web/FTP which are dynamic)
# 4. Uses AI to analyze remaining services with critical services context
# 5. Executes AI recommendations for stopping/disabling services
#
# Requirements:
#   - config.conf with OPENROUTER_API_KEY set
#   - Root/sudo privileges
#   - Parsed README data (from readme_parser.sh)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$LINUX_DIR/config.conf"

# Source config
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Config file not found at $CONFIG_FILE" >&2
    exit 1
fi

source "$CONFIG_FILE"

# Validate required config
if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
    echo "Error: OPENROUTER_API_KEY not set in $CONFIG_FILE" >&2
    exit 1
fi

OPENROUTER_ENDPOINT="https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL="${OPENROUTER_MODEL:-openai/gpt-4o-mini}"
DATA_DIR="${DATA_DIR:-/tmp/cp-linux-automation}"
MAX_SERVICES=200
LOG_PREFIX="[ServiceAudit]"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
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

# Detect init system (systemd or sysvinit/upstart)
detect_init_system() {
    if command -v systemctl &> /dev/null && systemctl --version &> /dev/null 2>&1; then
        echo "systemd"
    elif command -v service &> /dev/null; then
        echo "sysvinit"
    else
        echo "unknown"
    fi
}

# Service management functions
service_enable() {
    local service="$1"
    local init_system="$2"

    case "$init_system" in
        systemd)
            if systemctl is-enabled "$service" &>/dev/null; then
                log_info "$service is already enabled"
            else
                systemctl enable "$service" &>/dev/null || log_warn "Failed to enable $service"
                log_ok "Enabled $service"
            fi
            ;;
        sysvinit)
            if command -v update-rc.d &> /dev/null; then
                update-rc.d "$service" enable &>/dev/null || log_warn "Failed to enable $service"
            elif command -v chkconfig &> /dev/null; then
                chkconfig "$service" on &>/dev/null || log_warn "Failed to enable $service"
            fi
            log_ok "Enabled $service"
            ;;
    esac
}

service_disable() {
    local service="$1"
    local init_system="$2"

    case "$init_system" in
        systemd)
            if systemctl is-enabled "$service" &>/dev/null; then
                systemctl disable "$service" &>/dev/null || log_warn "Failed to disable $service"
                log_ok "Disabled $service"
            fi
            ;;
        sysvinit)
            if command -v update-rc.d &> /dev/null; then
                update-rc.d "$service" disable &>/dev/null || log_warn "Failed to disable $service"
            elif command -v chkconfig &> /dev/null; then
                chkconfig "$service" off &>/dev/null || log_warn "Failed to disable $service"
            fi
            log_ok "Disabled $service"
            ;;
    esac
}

service_start() {
    local service="$1"
    local init_system="$2"

    case "$init_system" in
        systemd)
            if systemctl is-active "$service" &>/dev/null; then
                log_info "$service is already running"
            else
                systemctl start "$service" &>/dev/null || log_warn "Failed to start $service"
                log_ok "Started $service"
            fi
            ;;
        sysvinit)
            service "$service" start &>/dev/null || log_warn "Failed to start $service"
            log_ok "Started $service"
            ;;
    esac
}

service_stop() {
    local service="$1"
    local init_system="$2"

    case "$init_system" in
        systemd)
            if systemctl is-active "$service" &>/dev/null; then
                systemctl stop "$service" &>/dev/null || log_warn "Failed to stop $service"
                log_ok "Stopped $service"
            fi
            ;;
        sysvinit)
            service "$service" stop &>/dev/null || log_warn "Failed to stop $service"
            log_ok "Stopped $service"
            ;;
    esac
}

service_exists() {
    local service="$1"
    local init_system="$2"

    case "$init_system" in
        systemd)
            systemctl list-unit-files "$service.service" &>/dev/null
            ;;
        sysvinit)
            service --status-all 2>/dev/null | grep -q "$service"
            ;;
    esac
}

# Install essential security packages
install_security_packages() {
    log_info "Installing essential security packages..."

    local packages=()

    # Check if apparmor is installed
    if ! dpkg -l | grep -q "^ii  apparmor "; then
        packages+=("apparmor")
    fi

    # Check if auditd is installed
    if ! dpkg -l | grep -q "^ii  auditd "; then
        packages+=("auditd")
    fi

    # Check if ufw is installed
    if ! dpkg -l | grep -q "^ii  ufw "; then
        packages+=("ufw")
    fi

    if [[ ${#packages[@]} -gt 0 ]]; then
        log_info "Installing: ${packages[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${packages[@]}" 2>/dev/null || log_warn "Some packages failed to install"
    else
        log_ok "All essential security packages already installed"
    fi
}

# Apply hardcoded service rules
apply_hardcoded_rules() {
    local init_system="$1"
    log_info "Applying hardcoded service rules..."

    local changes=0

    # Services to ALWAYS enable and start (essential security services)
    local enable_services=(
        "apparmor"
        "auditd"
        "ufw"
    )

    # Services to ALWAYS disable and stop (security risks)
    # NOTE: Web servers (apache2, nginx) and FTP (vsftpd, ftpd) are handled dynamically by AI
    local disable_services=(
        "cups"              # Printing service
        "cups-browsed"      # Printer discovery
        "transmission-daemon"  # BitTorrent client
        "deluge"            # BitTorrent client
        "deluged"           # BitTorrent daemon
        "rtorrent"          # BitTorrent client
        "qbittorrent"       # BitTorrent client
        "telnetd"           # Telnet server
        "rsh-server"        # RSH server
        "rlogin"            # Remote login
        "rexec"             # Remote execution
        "snmpd"             # SNMP (often not needed)
        "nfs-server"        # NFS server
        "nfs-kernel-server" # NFS kernel server
        "rpcbind"           # RPC (often not needed)
        "avahi-daemon"      # Service discovery (often not needed)
        "bluetooth"         # Bluetooth (often not needed)
    )

    # Enable and start essential services
    for service in "${enable_services[@]}"; do
        if service_exists "$service" "$init_system"; then
            service_enable "$service" "$init_system"
            service_start "$service" "$init_system"
            ((changes++))
        fi
    done

    # Disable and stop risky services
    for service in "${disable_services[@]}"; do
        if service_exists "$service" "$init_system"; then
            service_stop "$service" "$init_system"
            service_disable "$service" "$init_system"
            ((changes++))
        fi
    done

    log_ok "Hardcoded rules applied: $changes services modified"
}

# Get inventory of all services
get_service_inventory() {
    local init_system="$1"
    local output=""

    case "$init_system" in
        systemd)
            output=$(systemctl list-units --type=service --all --no-pager --no-legend | \
                awk '{print $1 "," $2 "," $3 "," $4}' | head -n "$MAX_SERVICES")
            ;;
        sysvinit)
            output=$(service --status-all 2>&1 | \
                awk '{status="unknown"; if ($2 == "+") status="running"; else if ($2 == "-") status="stopped"; print $3 "," status ",unknown,unknown"}' | \
                head -n "$MAX_SERVICES")
            ;;
    esac

    echo "$output"
}

# Load parsed README data
load_parsed_readme() {
    local parsed_file="$DATA_DIR/parsed_readme.json"

    if [[ ! -f "$parsed_file" ]]; then
        log_warn "Parsed README not found at $parsed_file"
        log_warn "Run readme_parser.sh first, or it will be auto-run by run.sh"
        echo "{}"
        return 1
    fi

    cat "$parsed_file"
}

# Build system prompt for OpenRouter
build_system_prompt() {
    local critical_services="$1"

    cat <<EOF
You are an assistant that analyzes Linux services for CyberPatriot competition images.
Your task is to identify which services should be STOPPED and DISABLED based on security best practices.

CRITICAL: The following services are explicitly marked as REQUIRED in the README and must NEVER be disabled:
$critical_services

Analyze the service inventory to determine which services are security risks and should be disabled.

Consider disabling:
- Web servers (apache2, nginx) UNLESS they are in the critical services list
- FTP servers (vsftpd, proftpd, ftpd) UNLESS they are in the critical services list
- Samba/SMB file sharing (smbd, nmbd) UNLESS they are in the critical services list
- VNC/remote desktop (vino, x11vnc) UNLESS they are in the critical services list
- Telnet (telnetd)
- Unnecessary database servers (mysql, postgresql) UNLESS they are in the critical services list
- Mail servers (postfix, sendmail, exim) UNLESS they are in the critical services list

DO NOT disable:
- Essential system services (sshd, cron, systemd services, dbus, etc.)
- Any service in the critical services list above
- Security services (apparmor, auditd, ufw, fail2ban, etc.)

Return ONLY a JSON object with this exact structure:
{
  "disable": ["service1", "service2", ...]
}

Rules:
- Only include services that appear in the provided inventory
- Use the exact service name from the inventory (e.g., "apache2.service" if that's what's shown)
- NEVER include services from the critical services list
- Be conservative: when in doubt, do not disable
- Return valid JSON only, no markdown, no explanations
EOF
}

# Call OpenRouter API for dynamic service analysis
analyze_services_with_ai() {
    local inventory="$1"
    local critical_services_json="$2"

    # Format critical services for the prompt
    local critical_services_list
    if [[ "$critical_services_json" == "[]" ]] || [[ -z "$critical_services_json" ]]; then
        critical_services_list="(none specified in README)"
    else
        critical_services_list=$(echo "$critical_services_json" | jq -r '.[] | "- " + .' | tr '\n' ' ')
    fi

    local system_prompt
    system_prompt=$(build_system_prompt "$critical_services_list")

    local user_prompt
    user_prompt=$(cat <<EOF
CRITICAL SERVICES (must NOT be disabled):
$critical_services_list

SERVICE INVENTORY:
$inventory

Analyze the above and return JSON with services to disable. Remember: NEVER disable critical services!
EOF
)

    # Build JSON request body
    local request_body
    request_body=$(jq -n \
        --arg model "$OPENROUTER_MODEL" \
        --arg system_prompt "$system_prompt" \
        --arg user_prompt "$user_prompt" \
        '{
            model: $model,
            temperature: 0,
            top_p: 1,
            max_tokens: 4000,
            messages: [
                {role: "system", content: $system_prompt},
                {role: "user", content: $user_prompt}
            ]
        }')

    # Make API request
    local response
    response=$(curl -s -X POST "$OPENROUTER_ENDPOINT" \
        -H "Authorization: Bearer $OPENROUTER_API_KEY" \
        -H "Content-Type: application/json" \
        -H "X-Title: CP-Linux-Service-Audit" \
        -d "$request_body")

    # Extract content from response
    local content
    content=$(echo "$response" | jq -r '.choices[0].message.content // empty')

    if [[ -z "$content" ]]; then
        log_error "OpenRouter returned empty content"
        echo "{\"disable\": []}"
        return 1
    fi

    # Strip markdown code fences if present
    content=$(echo "$content" | sed 's/^```json//g' | sed 's/^```//g' | sed 's/```$//g' | xargs)

    echo "$content"
}

# Apply AI recommendations
apply_ai_recommendations() {
    local recommendations="$1"
    local init_system="$2"
    local critical_services_json="$3"

    local changes=0

    # Parse disable array
    local disable_services
    disable_services=$(echo "$recommendations" | jq -r '.disable[]? // empty')

    if [[ -z "$disable_services" ]]; then
        log_info "AI provided no service disable recommendations"
        return 0
    fi

    # Build list of critical service names for checking
    local critical_services_list=()
    if [[ "$critical_services_json" != "[]" ]] && [[ -n "$critical_services_json" ]]; then
        while IFS= read -r svc; do
            critical_services_list+=("$svc")
        done < <(echo "$critical_services_json" | jq -r '.[]')
    fi

    while IFS= read -r service; do
        if [[ -n "$service" ]]; then
            # Remove .service suffix if present for service commands
            local service_name="${service%.service}"

            # Check if this service is in critical services list
            local is_critical=false
            for critical_svc in "${critical_services_list[@]}"; do
                if [[ "$service_name" == "$critical_svc" ]] || [[ "$service" == "$critical_svc" ]]; then
                    is_critical=true
                    break
                fi
            done

            if $is_critical; then
                log_warn "Skipping $service_name - marked as critical in README"
                continue
            fi

            if service_exists "$service_name" "$init_system"; then
                service_stop "$service_name" "$init_system"
                service_disable "$service_name" "$init_system"
                log_ok "AI directive: disabled and stopped $service_name"
                ((changes++))
            else
                log_warn "AI requested disabling unknown service: $service"
            fi
        fi
    done <<< "$disable_services"

    log_ok "AI recommendations applied: $changes services modified"
}

# Main execution
main() {
    log_info "Linux Service Auditing Module starting..."

    # Pre-flight checks
    check_root

    local init_system
    init_system=$(detect_init_system)
    log_info "Detected init system: $init_system"

    if [[ "$init_system" == "unknown" ]]; then
        log_error "Unknown init system, cannot proceed"
        exit 1
    fi

    # Install essential security packages
    install_security_packages

    # Apply hardcoded rules
    apply_hardcoded_rules "$init_system"

    # Load parsed README data
    log_info "Loading parsed README data..."
    local parsed_readme
    if parsed_readme=$(load_parsed_readme); then
        log_ok "Loaded parsed README data"
    else
        log_warn "No parsed README data available, skipping AI analysis"
        log_ok "Service auditing completed (hardcoded rules only)"
        exit 0
    fi

    # Extract critical services
    local critical_services
    critical_services=$(echo "$parsed_readme" | jq -c '.critical_services // []')

    local service_count
    service_count=$(echo "$critical_services" | jq 'length')

    if [[ $service_count -gt 0 ]]; then
        local services_list
        services_list=$(echo "$critical_services" | jq -r '.[] | "  - " + .')
        log_info "Critical services from README ($service_count):"
        echo "$services_list"
    else
        log_info "No critical services specified in README"
    fi

    # Get service inventory
    log_info "Gathering service inventory..."
    local inventory
    inventory=$(get_service_inventory "$init_system")

    if [[ -z "$inventory" ]]; then
        log_warn "Could not gather service inventory"
        log_ok "Service auditing completed (hardcoded rules only)"
        exit 0
    fi

    log_info "Found $(echo "$inventory" | wc -l) services"

    # AI analysis
    log_info "Sending service inventory and critical services to AI for analysis..."

    local ai_response
    if ai_response=$(analyze_services_with_ai "$inventory" "$critical_services"); then
        log_info "AI analysis complete, applying recommendations..."
        apply_ai_recommendations "$ai_response" "$init_system" "$critical_services"
    else
        log_warn "AI analysis failed, skipping dynamic recommendations"
    fi

    log_ok "Service auditing completed successfully"
}

# Run main function
main "$@"
