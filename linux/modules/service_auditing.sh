#!/bin/bash
#
# Linux Service Auditing Module for CyberPatriot
#
# This script:
# 1. Installs and enables essential security services (hardcoded)
# 2. Disables/stops risky services (hardcoded)
# 3. Uses AI to analyze remaining services dynamically with README context
# 4. Executes AI recommendations for stopping/disabling services
#
# Requirements:
#   - OPENROUTER_API_KEY environment variable
#   - Optional: OPENROUTER_MODEL (defaults to openai/gpt-4o-mini)
#   - Root/sudo privileges
#   - README file at standard CyberPatriot locations

set -euo pipefail

# Configuration
OPENROUTER_ENDPOINT="https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL="${OPENROUTER_MODEL:-openai/gpt-4o-mini}"
MAX_SERVICES=200
LOG_PREFIX="[ServiceAudit]"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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

# Check for required environment variables
check_env() {
    if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
        log_error "OPENROUTER_API_KEY environment variable not set"
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

# Install essential security packages (no apt update per requirements)
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
        # Use DEBIAN_FRONTEND=noninteractive to avoid prompts
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
    local disable_services=(
        "cups"              # Printing service
        "cups-browsed"      # Printer discovery
        "transmission-daemon"  # BitTorrent client
        "deluge"            # BitTorrent client
        "deluged"           # BitTorrent daemon
        "rtorrent"          # BitTorrent client
        "qbittorrent"       # BitTorrent client
        "apache2"           # Web server (unless needed per README)
        "nginx"             # Web server (unless needed per README)
        "vsftpd"            # FTP server
        "ftpd"              # FTP server
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
            # For sysvinit, use service --status-all
            output=$(service --status-all 2>&1 | \
                awk '{status="unknown"; if ($2 == "+") status="running"; else if ($2 == "-") status="stopped"; print $3 "," status ",unknown,unknown"}' | \
                head -n "$MAX_SERVICES")
            ;;
    esac

    echo "$output"
}

# Find README file
find_readme() {
    local readme_locations=(
        "/home/*/Desktop/README.html"
        "/home/*/Desktop/README.txt"
        "/home/*/Desktop/Readme.html"
        "/home/*/Desktop/readme.html"
        "/root/Desktop/README.html"
        "/root/Desktop/README.txt"
        "/opt/cyberpatriot/README.html"
        "/opt/cyberpatriot/README.txt"
    )

    for location in "${readme_locations[@]}"; do
        # Use globbing to expand wildcards
        for file in $location; do
            if [[ -f "$file" ]]; then
                echo "$file"
                return 0
            fi
        done
    done

    return 1
}

# Extract text from README
extract_readme_text() {
    local readme_file="$1"
    local text=""

    if [[ "$readme_file" == *.html ]]; then
        # Strip HTML tags if it's an HTML file
        text=$(cat "$readme_file" | sed 's/<[^>]*>//g' | tr -s '[:space:]' ' ')
    else
        text=$(cat "$readme_file")
    fi

    # Limit to 6000 characters to avoid token limits
    echo "${text:0:6000}"
}

# Build system prompt for OpenRouter
build_system_prompt() {
    cat <<'EOF'
You are an assistant that analyzes Linux services for CyberPatriot competition images.
Your task is to identify which services should be STOPPED and DISABLED based on security best practices and the README instructions.

Analyze the service inventory and README content to determine:
1. Services that are security risks and should be disabled (e.g., unnecessary network services, file sharing, remote access)
2. Services explicitly mentioned in the README as needing to be stopped or disabled
3. Services that are explicitly mentioned as CRITICAL or REQUIRED in the README should NOT be disabled

Return ONLY a JSON object with this exact structure:
{
  "disable": ["service1", "service2", ...]
}

Rules:
- Only include services that appear in the provided inventory
- Use the exact service name from the inventory (e.g., "apache2.service" not just "apache2")
- DO NOT disable essential system services (sshd, cron, systemd services, dbus, etc.)
- DO NOT disable services that the README explicitly states are required or critical
- Focus on security risks: web servers, FTP, Telnet, unnecessary network services, file sharing, remote desktop, etc.
- Be conservative: when in doubt, do not disable
- Return valid JSON only, no markdown, no explanations

Examples of services that are typically safe to disable (if not in README as critical):
- Web servers (apache2, nginx) unless README mentions web hosting
- FTP servers (vsftpd, proftpd)
- Samba/SMB file sharing (smbd, nmbd) unless README mentions file sharing
- VNC/remote desktop (vino, x11vnc) unless README mentions remote access
- Telnet (telnetd)
- Unnecessary print services (cups) if already handled
EOF
}

# Call OpenRouter API for dynamic service analysis
analyze_services_with_ai() {
    local inventory="$1"
    local readme_text="$2"

    local system_prompt
    system_prompt=$(build_system_prompt)

    local user_prompt
    user_prompt=$(cat <<EOF
README CONTENT:
$readme_text

SERVICE INVENTORY:
$inventory

Analyze the above and return JSON with services to disable.
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
    content=$(echo "$content" | sed 's/^```json//g' | sed 's/^```//g' | sed 's/```$//g')

    echo "$content"
}

# Apply AI recommendations
apply_ai_recommendations() {
    local recommendations="$1"
    local init_system="$2"

    local changes=0

    # Parse disable array
    local disable_services
    disable_services=$(echo "$recommendations" | jq -r '.disable[]? // empty')

    if [[ -z "$disable_services" ]]; then
        log_info "AI provided no service disable recommendations"
        return 0
    fi

    while IFS= read -r service; do
        if [[ -n "$service" ]]; then
            # Remove .service suffix if present for service commands
            local service_name="${service%.service}"

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
    check_env

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

    # Find and read README
    log_info "Looking for README file..."
    local readme_file
    if readme_file=$(find_readme); then
        log_ok "Found README: $readme_file"

        local readme_text
        readme_text=$(extract_readme_text "$readme_file")

        if [[ -n "$readme_text" ]]; then
            log_info "Sending service inventory and README to AI for analysis..."

            local ai_response
            if ai_response=$(analyze_services_with_ai "$inventory" "$readme_text"); then
                log_info "AI analysis complete, applying recommendations..."
                apply_ai_recommendations "$ai_response" "$init_system"
            else
                log_warn "AI analysis failed, skipping dynamic recommendations"
            fi
        else
            log_warn "README is empty, skipping AI analysis"
        fi
    else
        log_warn "No README found, skipping AI analysis"
    fi

    log_ok "Service auditing completed successfully"
}

# Run main function
main "$@"
