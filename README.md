# LoneWarrior: Autonomous Security Agent

<div align="center">

**Standalone, intelligent security protection that learns, detects, and acts autonomously**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://www.python.org/downloads/)
[![Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://www.linux.org/)

</div>

---

## 📖 About

LoneWarrior is an autonomous security agent that protects Linux systems by learning normal system behavior, detecting anomalies, and automatically responding to threats without human intervention. It combines behavioral baselining, multi-layered threat detection, and autonomous response capabilities into a single, lightweight security solution.

### Key Features

- **🧠 Behavioral Baseline Learning** - Learns what's normal for your system across multiple phases
- **🔍 Multi-Layer Detection** - Process, network, auth, file integrity, and threat intelligence
- **⚡ Autonomous Response** - Blocks IPs, terminates processes, enables containment automatically
- **🎯 Low False Positives** - Advanced correlation and confidence scoring reduce noise
- **🛡️ File Integrity Monitoring** - Real-time file change detection with webshell signatures
- **🌐 Threat Intelligence** - Built-in and external threat feeds (AbuseIPDB, Project Honey Pot)
- **🔄 Rollback Capability** - All autonomous actions can be undone
- **⚙️ Simple Deployment** - One-command installation via `install.sh`
- **📊 Web Dashboard** - Real-time monitoring and management interface
- **🔒 Secure by Design** - Database with 0600 permissions, privilege separation

---

## 🚀 Quick Start

### Prerequisites

- **OS**: Linux (Ubuntu 20.04+, Debian 10+, RHEL 8+, Kali Linux)
- **Python**: 3.9 or higher
- **Privileges**: Root access (for iptables, process termination)
- **Disk**: ~100MB free space
- **Memory**: ~256MB RAM minimum

### One-Command Installation

```bash
# Clone the repository
git clone https://github.com/0xshivangpatel/LoneWarrior.git
cd LoneWarrior

# Run the installation script (requires root)
sudo ./install.sh

# Start LoneWarrior
sudo systemctl start lonewarrior

# Enable autostart on boot
sudo systemctl enable lonewarrior

# Check status
sudo systemctl status lonewarrior
```

### Verify Installation

```bash
# Check LoneWarrior is running
lw status

# View recent detections
lw detections --limit 10

# View recent actions taken
lw actions --limit 10

# View system logs
lw logs --tail 50
```

---

## 📋 System Requirements

### Minimum System
- **CPU**: 1 core
- **RAM**: 256MB
- **Disk**: 100MB

### Recommended System
- **CPU**: 2+ cores
- **RAM**: 512MB - 1GB
- **Disk**: 500MB+

### External Services (Optional)
- **AbuseIPDB API Key**: For threat intelligence enrichment
- **Project Honey Pot**: Automatic download (no API key required)

---

## ⚙️ Configuration

### Main Configuration File

Location: `/etc/lonewarrior/config.yaml`

```yaml
general:
  data_dir: /var/lib/lonewarrior
  log_level: INFO

baseline:
  phase0_duration: 300      # Instant safety phase (5 minutes)
  phase1_duration: 900      # Fast baseline phase (15 minutes)
  phase2_duration: 3600     # Expanded baseline phase (1 hour)
  freeze_on_attack: true     # Freeze baseline during attacks

actions:
  enabled: true
  ip_block:
    enabled: true
    default_ttl: 900         # 15 minutes default block
  process_kill:
    enabled: true

threat_intel:
  use_builtin_blacklist: true
  reputation_tracking: true
  external_feeds:
    abuseipdb:
      enabled: true
      api_key: ""           # Set via: lw config set-api-key abuseipdb YOUR_KEY
    project_honeypot:
      enabled: true

file_integrity:
  enabled: true
  webshell_detection: true
  watch_paths:
    - /var/www
    - /etc
    - /root/.ssh
    - /home/*/.ssh
```

### Setting API Keys

```bash
# Set AbuseIPDB API key
sudo lw config set-api-key abuseipdb YOUR_API_KEY

# Show configured API keys (masked)
sudo lw config show-api-keys

# Restart after setting API keys
sudo systemctl restart lonewarrior
```

---

## 💻 CLI Commands

### Status & Monitoring

```bash
# Show overall system status
lw status

# Show dashboard metrics
lw dashboard

# Show recent detections
lw detections [options]
  --limit 20              # Show last 20 detections
  --type network_anomaly   # Filter by type
  --confidence 70          # Minimum confidence score
  --since "1 hour ago"   # Time range filter

# Show actions taken
lw actions [options]
  --limit 20
  --type ip_block
  --status success

# View logs
lw logs [options]
  --tail 100              # Show last 100 lines
  --follow                # Follow logs live
  --level ERROR            # Filter by log level
```

### Management Commands

```bash
# Start LoneWarrior
sudo systemctl start lonewarrior

# Stop LoneWarrior
sudo systemctl stop lonewarrior

# Restart LoneWarrior
sudo systemctl restart lonewarrior

# Enable autostart on boot
sudo systemctl enable lonewarrior

# Disable autostart on boot
sudo systemctl disable lonewarrior

# Reload configuration
sudo lw config reload
```

### Rollback Actions

```bash
# View rollback history
lw rollback list

# Rollback last action
lw rollback undo

# Rollback specific action by ID
lw rollback undo --action-id 123

# Rollback multiple actions
lw rollback undo --since "10 minutes ago"
```

### Baseline Management

```bash
# Check baseline phase
lw baseline phase

# Manually advance to next phase
lw baseline advance

# Freeze baseline (during attacks)
lw baseline freeze

# Unfreeze baseline
lw baseline unfreeze

# View baseline statistics
lw baseline stats
```

---

## 🔒 Security Features

### Detection Types

| Type | Description | Confidence |
|-------|-------------|-------------|
| **Invariant Violation** | Impossible events (web server spawning shell) | 90-99% |
| **FIM Hit** | File integrity monitoring matches | 85-95% |
| **Threat Intel Hit** | Known malicious IPs/domains | 70-95% |
| **Network Anomaly** | Unknown destinations/behaviors | 30-60% |
| **Baseline Deviation** | Unknown processes/connections | 25-50% |
| **Correlated Threat** | Multi-vector attack pattern | 40-80% |

### Response Actions

| Action | Description | Reversible |
|--------|-------------|-------------|
| **IP Block** | Block IP via iptables (with TTL) | ✅ Yes |
| **Process Kill** | Terminate suspicious process | ⚠️ No |
| **Rate Limit** | Throttle connections (rate limit) | ✅ Yes |
| **Containment Mode** | Full system lockdown (outbound blocked) | ✅ Yes |
| **User Disable** | Disable suspicious user account | ✅ Yes |
| **Container Stop** | Stop suspicious container | ✅ Yes |

### File Integrity Monitoring (FIM)

Watches the following paths by default:
- **Web Directories**: `/var/www`, `/usr/share/nginx`, `/usr/share/apache2`
- **System Configs**: `/etc`, `/etc/systemd/system`
- **SSH Keys**: `/root/.ssh`, `/home/*/.ssh`
- **Cron Jobs**: `/etc/cron.*`, `/var/spool/cron`
- **User Data**: `/home/*/public_html`

Webshell signatures detected:
- PHP eval/base64_decode patterns
- System/exec/shell_exec calls
- c99, r57, WSO shells
- And 10+ additional patterns

---

## 📊 Monitoring & Dashboard

### Web Dashboard

```bash
# Start web dashboard
sudo lw dashboard --port 8080

# Access at:
# http://localhost:8080
# http://YOUR_SERVER_IP:8080
```

**Dashboard Features**:
- Real-time detection feed
- Action history with status
- System health metrics
- Baseline phase indicators
- Threat intelligence hits
- Rollback interface
- Configuration management

### System Integration

LoneWarrior integrates with:
- **Journalctl** - System journal for events
- **Systemd** - Service management
- **iptables** - Network blocking
- **Auth Logs** - `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`, `/var/log/messages`
- **ProcFS** - Process information from `/proc`

---

## 🧪 Testing

### Run Full Test Suite

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test category
python -m pytest tests/test_actions.py -v
python -m pytest tests/test_core.py -v

# Run with coverage
python -m pytest tests/ --cov=lonewarrior --cov-report=html
```

### Attack Simulation

```bash
# Run attack simulator to test detection/response
python attack_simulator.py --intensity medium --mode sequential --duration 60

# Check logs for detections
sudo journalctl -u lonewarrior -f

# Verify actions taken
lw actions --limit 20
```

### Integration Testing

```bash
# Run comprehensive integration tests
python tests/test_end_to_end.py

# Run component isolation tests
python -m pytest tests/test_component_isolation.py -v
```

---

## 🔧 Troubleshooting

### LoneWarrior Not Starting

```bash
# Check service status
sudo systemctl status lonewarrior

# View service logs
sudo journalctl -u lonewarrior -n 100

# Check configuration
lw config validate
```

### High Memory Usage

```bash
# Check current memory usage
ps aux | grep lonewarrior

# Reduce baseline retention in config.yaml
baseline:
  history_retention_days: 7  # Default is 30

# Restart after config change
sudo systemctl restart lonewarrior
```

### False Positives

```bash
# Add IP to whitelist
sudo lw config whitelist add --ip 1.2.3.4

# Add process to whitelist
sudo lw config whitelist add --process "legitimate-app"

# Add user to whitelist
sudo lw config whitelist add --user "trusted-user"

# View current whitelist
sudo lw config whitelist list
```

### Rollback Failed

```bash
# Check rollback status
lw rollback list

# Force rollback of specific action
lw rollback undo --action-id 123 --force

# View rollback logs
lw logs --filter rollback
```

### IP Blocking Not Working

```bash
# Check iptables rules
sudo iptables -L -n

# Verify privilege helper
sudo ls -la /opt/LoneWarrior/scripts/lw-privilege-helper

# Test IP block manually
sudo iptables -A INPUT -s 1.2.3.4 -j DROP
# Verify: sudo iptables -L -n
# Remove: sudo iptables -D INPUT -s 1.2.3.4 -j DROP
```

### Database Issues

```bash
# Check database file
ls -la /var/lib/lonewarrior/lonewarrior.db

# Backup database
sudo cp /var/lib/lonewarrior/lonewarrior.db /var/lib/lonewarrior/lonewarrior.db.backup

# Reset database (CAUTION: deletes all data)
sudo systemctl stop lonewarrior
sudo rm /var/lib/lonewarrior/lonewarrior.db
sudo systemctl start lonewarrior
```

---

## 📁 File Locations

| Component | Path | Description |
|-----------|-------|-------------|
| **Main Config** | `/etc/lonewarrior/config.yaml` | Primary configuration |
| **Defaults** | `/opt/LoneWarrior/lonewarrior/config/defaults.yaml` | Default settings |
| **Database** | `/var/lib/lonewarrior/lonewarrior.db` | SQLite DB (0600 perms) |
| **Logs** | `/var/log/lonewarrior/lonewarrior.log` | Application logs |
| **Systemd Service** | `/etc/systemd/system/lonewarrior.service` | Service definition |
| **Blacklist** | `/opt/LoneWarrior/lonewarrior/threat_intel/blacklist_ips.txt` | Built-in IP blacklist |
| **Web Assets** | `/opt/LoneWarrior/lonewarrior/web/` | Dashboard files |

---

## 🔐 Security Considerations

### Database Security
- **File Permissions**: Database created with 0600 (owner read/write only)
- **Directory**: `/var/lib/lonewarrior` with 0700 (owner full access only)

### API Key Storage
- **No Hardcoded Keys**: API keys loaded from environment variables
- **Secure Storage**: `.env` file with 600 permissions
- **CLI Management**: `lw config set-api-key` for safe key input

### Privilege Separation
- **LoneWarrior**: Runs as root (required for iptables, process control)
- **Privilege Helper**: `/opt/LoneWarrior/scripts/lw-privilege-helper` for elevated operations
- **Minimal Scope**: Only privileges required for specific actions

### Network Security
- **Localhost Whitelisted**: `127.0.0.1`, `::1`, `localhost` never blocked
- **TTL on Blocks**: All IP blocks expire after default_ttl (15 minutes)
- **Rollback**: Every autonomous action can be undone

---

## 🤝 Contributing

### Development Setup

```bash
# Clone repository
git clone https://github.com/0xshivangpatel/LoneWarrior.git
cd LoneWarrior

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/ -v

# Format code (if using black)
black lonewarrior/
```

### Code Style

- **PEP 8** compliant
- **Type Hints** required for new functions
- **Docstrings** Google-style
- **Testing** pytest for all features

### Pull Requests

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

---

## 📄 License

Distributed under the **Apache License 2.0**. See [LICENSE](LICENSE) for more information.

---

## 🙏 Acknowledgments

- **Watchdog** - File system monitoring library
- **PyYAML** - Configuration parsing
- **pytest** - Testing framework
- **AbuseIPDB** - Threat intelligence feed
- **Project Honey Pot** - Community threat intelligence

---

## 📞 Support & Documentation

### Documentation
- **Installation Guide**: See [docs/INSTALLATION.md](docs/INSTALLATION.md)
- **VPS Deployment**: See [docs/VPS_DEPLOYMENT.md](docs/VPS_DEPLOYMENT.md)
- **Test Plan**: See [docs/V1_VPS_TEST_PLAN.md](docs/V1_VPS_TEST_PLAN.md)

### Getting Help
- **GitHub Issues**: https://github.com/0xshivangpatel/LoneWarrior/issues
- **Logs**: `sudo journalctl -u lonewarrior -f`
- **Status**: `lw status`

### Security Issues
For security vulnerabilities, please email: security@lonewarrior.ai (setup this address)

---

## 🗺️ Roadmap

### v1.1 (Planned)
- [ ] Enhanced ML-based anomaly detection
- [ ] Windows support
- [ ] Kubernetes container security
- [ ] Email/Slack alerts integration
- [ ] Mobile app for monitoring

### v1.2 (Planned)
- [ ] Distributed deployment coordination
- [ ] Automated threat hunting
- [ ] Integration with SIEM (Splunk, ELK)
- [ ] Forensics report generation

---

<div align="center">

**Built with ❤️ for autonomous security**

Made by: [0xshivangpatel](https://github.com/0xshivangpatel)

</div>
