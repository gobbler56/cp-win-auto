# Linux CyberPatriot Automation

Automated, modular hardening for **Ubuntu/Debian** Linux images used in CyberPatriot.

---

## What this does

- **Installs essential security services** (AppArmor, auditd, UFW)
- **Applies hardcoded service rules** for known security risks
- **Uses AI to analyze services dynamically** with README context
- **Stops and disables risky services** automatically

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
- `apache2`, `nginx` - Web servers (unless README specifies need)
- `vsftpd`, `ftpd` - FTP servers
- `telnetd` - Telnet server
- `rsh-server`, `rlogin`, `rexec` - Remote shell services
- `snmpd` - SNMP daemon
- `nfs-server`, `nfs-kernel-server` - NFS servers
- `rpcbind` - RPC bind service
- `avahi-daemon` - Service discovery
- `bluetooth` - Bluetooth services

### 2. Dynamic AI Analysis

The module sends the full service inventory and README content to OpenRouter's AI:
- AI identifies additional security risks
- AI respects services marked as "critical" in README
- AI returns recommendations for services to disable
- Script automatically applies AI recommendations

### 3. README Context Integration

The module searches for README files in standard locations:
- `/home/*/Desktop/README.html`
- `/root/Desktop/README.html`
- `/opt/cyberpatriot/README.html`
- And more...

The README content is parsed and sent to AI to ensure:
- Critical services mentioned in README are NOT disabled
- Services explicitly mentioned as needing to be stopped ARE stopped
- Context-aware decisions based on the specific competition scenario

---

## Requirements

- **Root/sudo privileges**
- **Internet connectivity** to reach OpenRouter
- **Environment variables:**
  - `OPENROUTER_API_KEY` - required
  - `OPENROUTER_MODEL` - optional (defaults to `openai/gpt-4o-mini`)

### Setting Environment Variables

Per-session:
```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
export OPENROUTER_MODEL="openai/gpt-4o-mini"
```

Persistent (add to `/etc/environment` or `~/.bashrc`):
```bash
echo 'export OPENROUTER_API_KEY="sk-or-v1-..."' | sudo tee -a /etc/environment
echo 'export OPENROUTER_MODEL="openai/gpt-4o-mini"' | sudo tee -a /etc/environment
```

---

## Quick Start

### Option 1: Direct Execution

```bash
# Set your API key
export OPENROUTER_API_KEY="sk-or-v1-..."

# Run the service auditing module
sudo -E ./linux/modules/service_auditing.sh
```

The `-E` flag preserves environment variables when using sudo.

### Option 2: Using the Launcher

```bash
# Set your API key
export OPENROUTER_API_KEY="sk-or-v1-..."

# Run the launcher
sudo -E ./linux/run.sh
```

---

## How It Works

1. **Pre-flight Checks**
   - Verifies root privileges
   - Checks for `OPENROUTER_API_KEY`
   - Detects init system (systemd or sysvinit)

2. **Install Security Packages**
   - Installs AppArmor if not present
   - Installs auditd if not present
   - Installs UFW if not present
   - No `apt update` is run (as per requirements)

3. **Apply Hardcoded Rules**
   - Enables and starts essential security services
   - Disables and stops known risky services
   - Reports changes made

4. **Gather Service Inventory**
   - Lists all services on the system
   - Captures service name, state, and status
   - Limits to 200 services to avoid token limits

5. **Find and Parse README**
   - Searches standard CyberPatriot locations
   - Extracts text from HTML or plain text README
   - Limits to 6000 characters for AI processing

6. **AI Analysis**
   - Sends service inventory + README to OpenRouter
   - AI returns recommendations for services to disable
   - AI respects README context and critical services

7. **Apply AI Recommendations**
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
[ServiceAudit] [INFO] Gathering service inventory...
[ServiceAudit] [INFO] Found 147 services
[ServiceAudit] [INFO] Looking for README file...
[ServiceAudit] [OK] Found README: /home/user/Desktop/README.html
[ServiceAudit] [INFO] Sending service inventory and README to AI for analysis...
[ServiceAudit] [INFO] AI analysis complete, applying recommendations...
[ServiceAudit] [OK] AI directive: disabled and stopped apache2
[ServiceAudit] [OK] AI directive: disabled and stopped vsftpd
[ServiceAudit] [OK] AI recommendations applied: 2 services modified
[ServiceAudit] [OK] Service auditing completed successfully
```

---

## Troubleshooting

### "OPENROUTER_API_KEY not set"
Set the environment variable and use `sudo -E` to preserve it:
```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
sudo -E ./linux/modules/service_auditing.sh
```

### "This script must be run as root"
Use sudo:
```bash
sudo -E ./linux/modules/service_auditing.sh
```

### "OpenRouter returned empty content"
- Check your API key is valid
- Ensure internet connectivity
- Verify the model name is correct
- Check OpenRouter status at https://openrouter.ai/

### "No README found"
Place your README file in one of these locations:
- `/home/[username]/Desktop/README.html`
- `/root/Desktop/README.html`
- `/opt/cyberpatriot/README.html`

The script will continue with hardcoded rules only if no README is found.

---

## Safety

- The script uses `set -euo pipefail` for safety
- Essential system services are never disabled
- AI recommendations are filtered to prevent disabling critical services
- All changes are logged with clear output
- Conservative approach: when in doubt, services are NOT disabled

---

## Advanced Usage

### Dry Run Mode

To see what would be changed without making changes, you can modify the script to add a dry-run flag, or review the output messages before confirming execution.

### Custom Service Lists

Edit the script to add custom services to the hardcoded enable/disable lists:

```bash
# Around line 180-190, add to enable_services array:
enable_services=(
    "apparmor"
    "auditd"
    "ufw"
    "your-custom-service"  # Add here
)

# Around line 200-220, add to disable_services array:
disable_services=(
    "cups"
    "transmission-daemon"
    "your-risky-service"  # Add here
)
```

---

## Integration with Full Automation

This module is designed to be part of a larger CyberPatriot automation suite. You can integrate it into your full hardening workflow:

1. User auditing
2. Password policies
3. **Service auditing** (this module)
4. Firewall configuration
5. Software updates
6. Prohibited files scan
7. And more...

---

## License

MIT - see `LICENSE` file in repository root.
