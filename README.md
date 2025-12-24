# LoneWarrior - Autonomous Security Agent

<div align="center">

**Standalone, intelligent security protection that learns, detects, and acts autonomously**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)

</div>

## 🛡️ What is LoneWarrior?

LoneWarrior is an autonomous security agent that protects Linux servers without requiring existing security infrastructure (SIEM, WAF, EDR). It learns your system's normal behavior, detects real attacks, and takes safe, reversible containment actions automatically.

### Key Features

- **🚀 Instant Protection** - Blocks known threats immediately (0-5 minutes)
- **🧠 Fast Learning** - Actionable baseline in 15-20 minutes
- **🎯 Real Detection** - Identifies actual attacks, not just alerts
- **⚡ Autonomous Response** - Takes safe, reversible actions without human intervention
- **💾 Resource Efficient** - Runs on 8GB VPS with ~500MB RAM footprint
- **🔌 Optional Integrations** - Works standalone or enhances Wazuh/ModSecurity/Suricata
- **🤖 Optional LLM** - Can use local or cloud LLMs for complex case analysis

## 🚦 How It Works - Phased Baseline

LoneWarrior uses a 4-phase graduated learning model:

| Phase | Duration | What It Learns | Actions Allowed |
|-------|----------|----------------|-----------------|
| **Phase 0** | 0-5 min | Nothing (threat intel only) | Known-bad IPs, obvious invariants |
| **Phase 1** | 15-20 min | Processes, ports, users, destinations | Temporary blocks, process kills |
| **Phase 2** | 1-2 hours | Rate patterns, refined baselines | Stronger containment, longer TTLs |
| **Phase 3** | Forever | Continuous drift tracking | Full capability + baseline freeze during attacks |

**🚨 Critical Safety**: Baseline learning **freezes completely** during suspicious activity to prevent "learning the attack as normal."


## 🚀 Quick Start

\`\`\`bash
# Clone the repository
git clone https://github.com/CoderShivang/LoneWarrior.git
cd LoneWarrior

# Run the installer (one-command setup!)
sudo ./install.sh
\`\`\`

### Installation Process
The \`install.sh\` script handles everything:
- ✅ Installs Python dependencies
- ✅ Creates system directories (\`/etc/lonewarrior\`, \`/var/lib/lonewarrior\`, \`/var/log/lonewarrior\`)
- ✅ Installs and enables systemd service
- ✅ Sets up log rotation
- ✅ Creates \`.env\` file for API keys (see below)
- ✅ Sets proper file permissions

### ⚙️ Configuration - API Keys

LoneWarrior integrates with external threat intelligence sources for enhanced protection:

#### AbuseIPDB (Recommended)
Get your free API key: https://www.abuseipdb.com/

\`\`\`bash
# Set API key after installation
sudo lw config set-api-key abuseipdb YOUR_API_KEY_HERE

# Or read from file
sudo lw config set-api-key abuseipdb -f /path/to/key.txt
\`\`\`

#### Project Honey Pot (Free, No Key Required)
Automatically downloads known malicious IPs from Project Honey Pot.

\`\`\`bash
# Enable (already enabled by default)
# No API key needed!
\`\`\`

### 🚦 Manual Start

\`\`\`bash
# Start the service
sudo systemctl start lonewarrior

# Check status
sudo systemctl status lonewarrior

# View logs
sudo journalctl -u lonewarrior -f
\`\`\`

### 📊 Monitoring

\`\`\`bash
# View live status
lw status

# View recent detections
lw detections

# View action history
lw actions

# View baselines
lw baseline

# Show API keys (masked)
lw config show-api-keys
\`\`\`

