# LoneWarrior Installation Guide

## Prerequisites

- Linux system (Ubuntu 20.04+, Debian 10+, or RHEL 8+)
- Root access
- Python 3.9 or higher
- 2GB RAM minimum (8GB recommended)
- 5GB disk space

## Quick Install

```bash
# Clone repository
git clone https://github.com/yourusername/lonewarrior.git
cd lonewarrior

# Run installer
sudo bash install.sh
```

The installer will:
1. Detect your OS and install dependencies
2. Install Python packages
3. Create required directories
4. Copy default configuration
5. Install and optionally start systemd service

## Manual Installation

If you prefer manual installation:

###  1. Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv iptables
```

**RHEL/CentOS:**
```bash
sudo yum install -y python3 python3-pip iptables
```

### 2. Install Python Package

```bash
sudo pip3 install -e .
```

### 3. Create Directories

```bash
sudo mkdir -p /var/lib/lonewarrior
sudo mkdir -p /var/log/lonewarrior
sudo mkdir -p /etc/lonewarrior
```

### 4. Copy Configuration

```bash
sudo cp lonewarrior/config/defaults.yaml /etc/lonewarrior/config.yaml
```

### 5. Install systemd Service

```bash
sudo cp systemd/lonewarrior.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable lonewarrior
sudo systemctl start lonewarrior
```

## Verification

Check that LoneWarrior is running:

```bash
# Check service status
sudo systemctl status lonewarrior

# View status via CLI
lw status

# View logs
sudo tail -f /var/log/lonewarrior/lonewarrior.log
```

## Initial Configuration

Edit `/etc/lonewarrior/config.yaml` to customize:

- Watch directories for FIM
- Confidence thresholds
- Integration settings (Wazuh, ModSecurity, Suricata)
- LLM preferences

After editing, restart the service:

```bash
sudo systemctl restart lonewarrior
```

## Uninstallation

```bash
sudo bash uninstall.sh
```

This will:
- Stop the service
- Remove iptables rules
- Optionally remove logs and database
- Remove systemd service

## Troubleshooting

### Service won't start

Check logs:
```bash
sudo journalctl -u lonewarrior -f
```

### Permission errors

Ensure running as root:
```bash
sudo systemctl restart lonewarrior
```

### Database issues

Reset database (⚠️ loses all data):
```bash
sudo rm /var/lib/lonewarrior/lonewarrior.db
sudo systemctl restart lonewarrior
```
