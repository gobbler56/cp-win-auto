#!/bin/bash
#
# README Parser Module for Linux CyberPatriot Automation
#
# This module:
# 1. Finds and reads the README file
# 2. Sends it to OpenRouter for parsing
# 3. Extracts structured data (users, admins, critical services, etc.)
# 4. Saves parsed data to JSON file for other modules to use
#
# Output: JSON file at $DATA_DIR/parsed_readme.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$LINUX_DIR/config.conf"

# Source config
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Config file not found at $CONFIG_FILE" >&2
    exit 1
fi

# Load config
source "$CONFIG_FILE"

# Validate required config
if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
    echo "Error: OPENROUTER_API_KEY not set in $CONFIG_FILE" >&2
    exit 1
fi

OPENROUTER_ENDPOINT="https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL="${OPENROUTER_MODEL:-openai/gpt-4o-mini}"
DATA_DIR="${DATA_DIR:-/tmp/cp-linux-automation}"
LOG_PREFIX="[ReadmeParser]"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

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

# Find README file
find_readme() {
    local IFS=','
    local locations=($README_LOCATIONS)

    for location_pattern in "${locations[@]}"; do
        location_pattern=$(echo "$location_pattern" | xargs)  # trim whitespace
        for file in $location_pattern; do
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
        # Strip HTML tags
        text=$(cat "$readme_file" | sed 's/<script[^>]*>.*<\/script>//g' | sed 's/<style[^>]*>.*<\/style>//g' | sed 's/<[^>]*>//g' | tr -s '[:space:]' ' ')
    else
        text=$(cat "$readme_file")
    fi

    echo "$text"
}

# Build system prompt for README parsing
build_system_prompt() {
    cat <<'EOF'
You are a STRICT extractor for CyberPatriot READMEs (Linux systems).
Return ONLY minified JSON, no prose, no markdown, no code fences.
If something is not present, return an empty array [] or empty object {} as appropriate.

Contract (keys and types are REQUIRED):
{
  "all_users": [ { "name": "string", "account_type": "standard|admin", "groups": ["string", ...] }, ... ],
  "recent_hires": [ { "name": "string", "account_type": "standard|admin", "groups": ["string", ...] }, ... ],
  "terminated_users": ["string", ...],
  "critical_services": ["string", ...]
}

Rules:
- Use the README's own lists as ground truth; do not hallucinate names.
- Include every allowed/authorized person under "all_users" with their account_type (admin if they're an administrator, otherwise standard). Include any groups if listed.
- Put ONLY newly required accounts under "recent_hires".
- Put ONLY explicitly unauthorized or removed users under "terminated_users".
- For "critical_services", include service names that are explicitly mentioned as required, critical, or must be running.
  Examples: "SSH must remain enabled", "Apache web server is required for the company website", "MySQL database must be running"
- Use standard Linux service names (sshd, apache2, nginx, mysql, postgresql, vsftpd, etc.)
- If a service is mentioned as needing to be stopped or disabled, DO NOT include it in critical_services.
- Do not include textual explanations. Output MUST be valid JSON, a single object, no trailing commas.

Examples:
INPUT (plain text snippet):
"Critical Information:
- The company website is hosted on this server (Apache)
- SSH access must remain enabled for remote administration
- Remove unauthorized user darkarmy
- Create user account for user penguru
- Disable FTP service (not needed)"

VALID OUTPUT:
{"all_users":[{"name":"penguru","account_type":"standard","groups":[]}],"recent_hires":[{"name":"penguru","account_type":"standard","groups":[]}],"terminated_users":["darkarmy"],"critical_services":["apache2","sshd"]}
EOF
}

# Parse README with OpenRouter
parse_readme() {
    local readme_text="$1"

    local system_prompt
    system_prompt=$(build_system_prompt)

    # Build JSON request
    local request_body
    request_body=$(jq -n \
        --arg model "$OPENROUTER_MODEL" \
        --arg system_prompt "$system_prompt" \
        --arg user_prompt "$readme_text" \
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
        -H "X-Title: CP-Linux-Readme-Parser" \
        -d "$request_body")

    # Extract content
    local content
    content=$(echo "$response" | jq -r '.choices[0].message.content // empty')

    if [[ -z "$content" ]]; then
        log_error "OpenRouter returned empty content"
        return 1
    fi

    # Strip markdown code fences if present
    content=$(echo "$content" | sed 's/^```json//g' | sed 's/^```//g' | sed 's/```$//g' | xargs)

    # Validate JSON
    if ! echo "$content" | jq . >/dev/null 2>&1; then
        log_error "OpenRouter returned invalid JSON"
        log_error "Response: $content"
        return 1
    fi

    echo "$content"
}

# Main execution
main() {
    log_info "README Parser Module starting..."

    # Create data directory
    mkdir -p "$DATA_DIR"

    # Find README
    log_info "Looking for README file..."
    local readme_file
    if readme_file=$(find_readme); then
        log_ok "Found README: $readme_file"
    else
        log_warn "No README found, creating empty parsed data"

        # Create empty parsed data
        local empty_data
        empty_data=$(jq -n '{
            all_users: [],
            recent_hires: [],
            terminated_users: [],
            critical_services: [],
            source_file: null,
            parsed_at: (now | strftime("%Y-%m-%d %H:%M:%S"))
        }')

        echo "$empty_data" > "$DATA_DIR/parsed_readme.json"
        log_ok "Created empty parsed data at $DATA_DIR/parsed_readme.json"
        return 0
    fi

    # Extract README text
    log_info "Extracting README content..."
    local readme_text
    readme_text=$(extract_readme_text "$readme_file")

    if [[ -z "$readme_text" ]]; then
        log_error "README file is empty"
        exit 1
    fi

    log_info "README content: ${#readme_text} characters"

    # Parse with OpenRouter
    log_info "Sending README to OpenRouter for parsing..."
    local parsed_json
    if ! parsed_json=$(parse_readme "$readme_text"); then
        log_error "Failed to parse README"
        exit 1
    fi

    log_ok "README parsed successfully"

    # Add metadata
    local final_json
    final_json=$(echo "$parsed_json" | jq \
        --arg source "$readme_file" \
        --arg timestamp "$(date '+%Y-%m-%d %H:%M:%S')" \
        '. + {source_file: $source, parsed_at: $timestamp}')

    # Save to file
    echo "$final_json" > "$DATA_DIR/parsed_readme.json"
    log_ok "Saved parsed data to $DATA_DIR/parsed_readme.json"

    # Display summary
    local user_count
    local hire_count
    local terminated_count
    local service_count

    user_count=$(echo "$final_json" | jq '.all_users | length')
    hire_count=$(echo "$final_json" | jq '.recent_hires | length')
    terminated_count=$(echo "$final_json" | jq '.terminated_users | length')
    service_count=$(echo "$final_json" | jq '.critical_services | length')

    log_info "Parsed: $user_count users, $hire_count new hires, $terminated_count terminated, $service_count critical services"

    if [[ $service_count -gt 0 ]]; then
        local services
        services=$(echo "$final_json" | jq -r '.critical_services | join(", ")')
        log_info "Critical services: $services"
    fi
}

main "$@"
