# Linux CyberPatriot Automation

Automated, modular hardening for **Ubuntu/Debian** Linux images used in CyberPatriot.

---

## What this does

- **Parses README once** and shares data across all modules
- **Installs essential security services** (AppArmor, auditd, UFW)
- **Applies hardcoded service rules** for known security risks
- **Uses AI to analyze services dynamically** with critical services context from README
- **Stops and disables risky services** automatically (except those marked as critical)

---

## Architecture

### Module Flow

```
1. README Parser (readme_parser.sh)
   ↓ Parses README with OpenRouter
   ↓ Extracts: users, admins, critical_services, terminated_users
   ↓ Saves to: /tmp/cp-linux-automation/parsed_readme.json

2. Service Auditing (service_auditing.sh)
   ↓ Reads parsed README data
   ↓ Applies hardcoded rules
   ↓ Sends service inventory + critical_services to AI
   ↓ AI returns services to disable (respecting critical services)
   ↓ Applies AI recommendations

3. [Future modules can read parsed_readme.json]
```

### Shared Configuration

All modules read from `linux/config.conf`:
- `OPENROUTER_API_KEY` - Your OpenRouter API key
- `OPENROUTER_MODEL` - AI model to use (default: openai/gpt-4o-mini)
- `DATA_DIR` - Where parsed data is stored (default: /tmp/cp-linux-automation)
- `README_LOCATIONS` - Comma-separated paths to search for README

---

## Service Auditing Module

The service auditing module performs three key functions:

### 1. Hardcoded Security Rules (Always Applied)

**Services ALWAYS enabled and started:**
- `apparmor` - Mandatory Access Control
- `auditd` - System auditing daemon
- `ufw` - Uncomplicated Firewall

**Services ALWAYS disabled and stopped:**
- `cups`, `cups-browsed` - Printing services
- `transmission-daemon`, `deluge`, `deluged`, `rtorrent`, `qbittorrent` - BitTorrent clients
- `telnetd` - Telnet server
- `rsh-server`, `rlogin`, `rexec` - Remote shell services
- `snmpd` - SNMP daemon
- `nfs-server`, `nfs-kernel-server` - NFS servers
- `rpcbind` - RPC bind service
- `avahi-daemon` - Service discovery
- `bluetooth` - Bluetooth services

**Services handled DYNAMICALLY by AI** (based on README):
- `apache2`, `nginx` - Web servers (disabled unless README marks as critical)
- `vsftpd`, `ftpd` - FTP servers (disabled unless README marks as critical)
- `mysql`, `postgresql` - Database servers (disabled unless README marks as critical)
- `smbd`, `nmbd` - Samba file sharing (disabled unless README marks as critical)
- And more...

### 2. Dynamic AI Analysis

The module sends the service inventory and **critical_services from parsed README** to OpenRouter:
- AI identifies additional security risks
- AI NEVER disables services marked as "critical" in README
- AI returns recommendations for services to disable
- Script automatically applies AI recommendations
- Additional safety check: script double-checks critical services list before disabling

### 3. README Context Integration

The README is parsed ONCE by `readme_parser.sh` and the structured data is shared:

**Parsed Data Structure:**
```json
{
  "all_users": [{"name": "alice", "account_type": "admin", "groups": ["sudo"]}],
  "recent_hires": [{"name": "bob", "account_type": "standard", "groups": []}],
  "terminated_users": ["darkarmy", "hacker"],
  "critical_services": ["apache2", "mysql", "sshd"],
  "source_file": "/home/user/Desktop/README.html",
  "parsed_at": "2025-11-05 12:34:56"
}
```

The `critical_services` array is extracted by AI from statements like:
- "The company website is hosted on this server (Apache must remain running)"
- "MySQL database is required for the application"
- "SSH access must be enabled for remote administration"

---

## Requirements

- **Root/sudo privileges**
- **Internet connectivity** to reach OpenRouter
- **Configuration file:** `linux/config.conf` with OPENROUTER_API_KEY set

---

## Quick Start

### 1. Configure

Edit `linux/config.conf` and set your API key:

```bash
# Edit the config file
nano linux/config.conf

# Set this line:
OPENROUTER_API_KEY="sk-or-v1-..."
```

### 2. Run

```bash
# Run all modules (recommended)
sudo ./linux/run.sh

# Or run individual modules:
sudo ./linux/modules/readme_parser.sh
sudo ./linux/modules/service_auditing.sh
```

**Note:** No need for `sudo -E` anymore - the API key is read from config.conf!

---

## How It Works

### README Parser Module

1. **Find README** - Searches standard CyberPatriot locations
2. **Extract Text** - Strips HTML tags if needed
3. **Send to OpenRouter** - AI extracts structured data
4. **Save JSON** - Stores parsed data for other modules to use

### Service Auditing Module

1. **Pre-flight Checks**
   - Verifies root privileges
   - Reads API key from config.conf
   - Detects init system (systemd or sysvinit)

2. **Install Security Packages**
   - Installs AppArmor if not present
   - Installs auditd if not present
   - Installs UFW if not present
   - No `apt update` is run

3. **Apply Hardcoded Rules**
   - Enables and starts essential security services
   - Disables and stops known risky services (torrents, printing, etc.)
   - Web/FTP/databases are NOT hardcoded - handled by AI

4. **Load Parsed README**
   - Reads `/tmp/cp-linux-automation/parsed_readme.json`
   - Extracts `critical_services` array

5. **Gather Service Inventory**
   - Lists all services on the system
   - Captures service name, state, and status
   - Limits to 200 services to avoid token limits

6. **AI Analysis**
   - Sends service inventory + critical_services to OpenRouter
   - AI prompt explicitly lists critical services as "MUST NEVER DISABLE"
   - AI returns recommendations for services to disable
   - AI respects critical services and essential system services

7. **Apply AI Recommendations**
   - Double-checks: if service is in critical_services list, skip it
   - Stops and disables services recommended by AI
   - Reports each change made
   - Logs warnings for unknown services

---

## Supported Distributions

- Ubuntu 14.04+ (Trusty, Xenial, Bionic, Focal, Jammy)
- Debian 8+ (Jessie, Stretch, Buster, Bullseye)
- Linux Mint 17+

Both **systemd** and **sysvinit/upstart** init systems are supported.

---

## Output Example

```
========================================
  Linux CyberPatriot Automation
========================================
[INFO] Starting Linux hardening automation...
[OK] Pre-flight checks passed

[INFO] Running README Parser Module...

[ReadmeParser] [INFO] README Parser Module starting...
[ReadmeParser] [INFO] Looking for README file...
[ReadmeParser] [OK] Found README: /home/user/Desktop/README.html
[ReadmeParser] [INFO] Extracting README content...
[ReadmeParser] [INFO] README content: 3847 characters
[ReadmeParser] [INFO] Sending README to OpenRouter for parsing...
[ReadmeParser] [OK] README parsed successfully
[ReadmeParser] [OK] Saved parsed data to /tmp/cp-linux-automation/parsed_readme.json
[ReadmeParser] [INFO] Parsed: 5 users, 2 new hires, 3 terminated, 2 critical services
[ReadmeParser] [INFO] Critical services: apache2, mysql
[OK] README Parser Module completed

[INFO] Running Service Auditing Module...

[ServiceAudit] [INFO] Linux Service Auditing Module starting...
[ServiceAudit] [INFO] Detected init system: systemd
[ServiceAudit] [INFO] Installing essential security packages...
[ServiceAudit] [OK] All essential security packages already installed
[ServiceAudit] [INFO] Applying hardcoded service rules...
[ServiceAudit] [OK] Enabled apparmor
[ServiceAudit] [OK] Started apparmor
[ServiceAudit] [OK] Enabled auditd
[ServiceAudit] [OK] Started auditd
[ServiceAudit] [OK] Enabled ufw
[ServiceAudit] [OK] Started ufw
[ServiceAudit] [OK] Stopped cups
[ServiceAudit] [OK] Disabled cups
[ServiceAudit] [OK] Hardcoded rules applied: 8 services modified
[ServiceAudit] [INFO] Loading parsed README data...
[ServiceAudit] [OK] Loaded parsed README data
[ServiceAudit] [INFO] Critical services from README (2):
  - apache2
  - mysql
[ServiceAudit] [INFO] Gathering service inventory...
[ServiceAudit] [INFO] Found 147 services
[ServiceAudit] [INFO] Sending service inventory and critical services to AI for analysis...
[ServiceAudit] [INFO] AI analysis complete, applying recommendations...
[ServiceAudit] [OK] AI directive: disabled and stopped vsftpd
[ServiceAudit] [OK] AI directive: disabled and stopped telnetd
[ServiceAudit] [WARN] Skipping apache2 - marked as critical in README
[ServiceAudit] [WARN] Skipping mysql - marked as critical in README
[ServiceAudit] [OK] AI recommendations applied: 2 services modified
[ServiceAudit] [OK] Service auditing completed successfully
[OK] Service Auditing Module completed

========================================
  All modules completed successfully!
========================================
```

---

## Troubleshooting

### "Config file not found"
Create the config file and set your API key:
```bash
nano linux/config.conf
# Add: OPENROUTER_API_KEY="sk-or-v1-..."
```

### "OPENROUTER_API_KEY not set in config.conf"
Edit the config file and add your API key:
```bash
nano linux/config.conf
# Set: OPENROUTER_API_KEY="sk-or-v1-..."
```

### "This script must be run as root"
Use sudo:
```bash
sudo ./linux/run.sh
```

### "OpenRouter returned empty content"
- Check your API key is valid
- Ensure internet connectivity
- Verify the model name is correct
- Check OpenRouter status at https://openrouter.ai/

### "Parsed README not found"
Run the full automation with `run.sh` instead of individual modules, or run the parser first:
```bash
sudo ./linux/modules/readme_parser.sh
sudo ./linux/modules/service_auditing.sh
```

### "No README found"
The parser will create an empty parsed data file and continue. Place your README in:
- `/home/[username]/Desktop/README.html`
- `/root/Desktop/README.html`
- `/opt/cyberpatriot/README.html`

---

## Safety Features

- **Parse Once, Use Everywhere:** README is parsed once, all modules share the data
- **Critical Services Protected:** AI is told which services are critical, and script double-checks
- **Conservative AI:** When in doubt, AI does not disable services
- **Essential Services Protected:** AI never disables sshd, cron, systemd, dbus, etc.
- **All Changes Logged:** Clear output shows every action taken
- **Graceful Degradation:** If README not found or AI fails, hardcoded rules still apply

---

## Configuration Reference

### config.conf

```bash
# Required: Your OpenRouter API key
OPENROUTER_API_KEY="sk-or-v1-..."

# Optional: AI model (default: openai/gpt-4o-mini)
OPENROUTER_MODEL="openai/gpt-4o-mini"

# Optional: README search locations (comma-separated)
README_LOCATIONS="/home/*/Desktop/README.html,/root/Desktop/README.html"

# Optional: Data directory for parsed README (default: /tmp/cp-linux-automation)
DATA_DIR="/tmp/cp-linux-automation"

# Optional: Log level (default: INFO)
LOG_LEVEL="INFO"
```

---

## Extending with New Modules

To add a new module:

1. Create `/linux/modules/your_module.sh`
2. Source the config: `source "$LINUX_DIR/config.conf"`
3. Read parsed README: `parsed=$(cat "$DATA_DIR/parsed_readme.json")`
4. Extract what you need: `critical_services=$(echo "$parsed" | jq '.critical_services')`
5. Add to `run.sh` to run automatically

Example:
```bash
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX_DIR="$(dirname "$SCRIPT_DIR")"
source "$LINUX_DIR/config.conf"

# Read parsed README
parsed=$(cat "$DATA_DIR/parsed_readme.json")
users=$(echo "$parsed" | jq -r '.all_users[].name')

# Do your thing...
```

---

## License

MIT - see `LICENSE` file in repository root.
