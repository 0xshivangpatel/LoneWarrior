#!/bin/bash
# LoneWarrior Installation Script
# Supports Ubuntu/Debian, RHEL/CentOS/Fedora
# Ensures LoneWarrior NEVER goes offline with watchdog and auto-restart

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           LoneWarrior - Autonomous Security Agent            ║"
echo "║                      Installation Script                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Configuration
INSTALL_DIR="/opt/LoneWarrior"
VENV_DIR="$INSTALL_DIR/venv"
DATA_DIR="/var/lib/lonewarrior"
LOG_DIR="/var/log/lonewarrior"
CONFIG_DIR="/etc/lonewarrior"

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# Check if we're running from the correct directory
if [ ! -d "$(dirname "$0")/lonewarrior" ] && [ ! -d "$INSTALL_DIR/lonewarrior" ]; then
    echo -e "${RED}Error: Cannot find lonewarrior source directory${NC}"
    echo "Please run this script from the LoneWarrior repository root"
    echo "or ensure $INSTALL_DIR exists with the source code."
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
    echo -e "${GREEN}✓ Detected OS: $OS $VERSION${NC}"
else
    echo -e "${YELLOW}Could not detect OS. Assuming Debian-based.${NC}"
    OS="debian"
fi

# Install system dependencies
echo -e "${BLUE}Installing system dependencies...${NC}"
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv python3-full iptables conntrack
elif [ "$OS" = "centos" ] || [ "$OS" = "rhel" ] || [ "$OS" = "fedora" ] || [ "$OS" = "rocky" ]; then
    if command -v dnf &> /dev/null; then
        dnf install -y python3 python3-pip iptables conntrack-tools
    else
        yum install -y python3 python3-pip iptables conntrack-tools
    fi
elif [ "$OS" = "arch" ]; then
    # Use -Syu to avoid partial upgrade (security best practice)
    pacman -Syu --noconfirm python python-pip iptables conntrack-tools
fi
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Create directories
echo -e "${BLUE}Creating directories...${NC}"
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR/snapshots"
mkdir -p "$DATA_DIR/backups"
echo -e "${GREEN}✓ Directories created${NC}"

# Copy source files to install directory
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ "$SOURCE_DIR" != "$INSTALL_DIR" ]; then
    echo -e "${BLUE}Copying source files to $INSTALL_DIR...${NC}"
    mkdir -p "$INSTALL_DIR"
    # Copy all files except venv and __pycache__
    rsync -a --exclude='venv' --exclude='__pycache__' --exclude='*.pyc' --exclude='.git' "$SOURCE_DIR/" "$INSTALL_DIR/" 2>/dev/null || {
        # Fallback if rsync not available
        cp -r "$SOURCE_DIR"/* "$INSTALL_DIR/" 2>/dev/null || true
        rm -rf "$INSTALL_DIR/venv" 2>/dev/null || true
    }
    echo -e "${GREEN}✓ Source files copied${NC}"
fi

# Create virtual environment and install package
echo -e "${BLUE}Setting up Python virtual environment...${NC}"
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

echo -e "${BLUE}Installing Python dependencies...${NC}"
"$VENV_DIR/bin/pip" install --upgrade pip -q

# Install requirements first
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
    echo -e "${GREEN}✓ Requirements installed${NC}"
else
    # Fallback: install core dependencies manually
    "$VENV_DIR/bin/pip" install psutil watchdog pyyaml -q
fi

# Install lonewarrior package (REQUIRED - do not silently fail)
echo -e "${BLUE}Installing LoneWarrior package...${NC}"
if [ -f "$INSTALL_DIR/setup.py" ] || [ -f "$INSTALL_DIR/pyproject.toml" ]; then
    "$VENV_DIR/bin/pip" install -e "$INSTALL_DIR" || {
        echo -e "${RED}Error: Failed to install lonewarrior package${NC}"
        echo "Please check $INSTALL_DIR/setup.py or pyproject.toml"
        exit 1
    }
else
    echo -e "${RED}Error: No setup.py or pyproject.toml found in $INSTALL_DIR${NC}"
    exit 1
fi

# Verify installation
"$VENV_DIR/bin/python" -c "import lonewarrior" || {
    echo -e "${RED}Error: lonewarrior module not found after installation${NC}"
    exit 1
}
echo -e "${GREEN}✓ LoneWarrior package installed${NC}"

# Install config
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    echo -e "${BLUE}Installing default configuration...${NC}"
    if [ -f "$INSTALL_DIR/lonewarrior/config/defaults.yaml" ]; then
        cp "$INSTALL_DIR/lonewarrior/config/defaults.yaml" "$CONFIG_DIR/config.yaml"
    else
        cat > "$CONFIG_DIR/config.yaml" << 'CONFIGEOF'
general:
  data_dir: /var/lib/lonewarrior
  log_level: INFO
  
learning:
  phase1_duration: 1200
  phase2_duration: 7200

actions:
  enabled: true
  auto_block: true
  block_duration: 3600

containment:
  whitelist_ips:
    - "127.0.0.1"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
  allowed_dns_servers:
    - "8.8.8.8"
    - "1.1.1.1"

file_integrity:
  enabled: true
  paths:
    - /etc
    - /usr/bin
    - /var/www
CONFIGEOF
    fi
    echo -e "${GREEN}✓ Configuration installed${NC}"
fi

# Create CLI wrapper
echo -e "${BLUE}Installing CLI wrapper...${NC}"
cat > /usr/local/bin/lw << 'CLIEOF'
#!/bin/bash
/opt/LoneWarrior/venv/bin/python -m lonewarrior.cli.main "$@"
CLIEOF
chmod +x /usr/local/bin/lw
echo -e "${GREEN}✓ CLI installed (use 'lw' command)${NC}"

# Install main systemd service with RELIABILITY FEATURES
echo -e "${BLUE}Installing systemd service with auto-recovery...${NC}"
cat > /etc/systemd/system/lonewarrior.service << EOF
[Unit]
Description=LoneWarrior Autonomous Security Agent
Documentation=https://github.com/CoderShivang/LoneWarrior
After=network-online.target
Wants=network-online.target
# Allow 5 restarts in 5 minutes before giving up
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python -m lonewarrior --config $CONFIG_DIR/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID

# === RELIABILITY: NEVER GO OFFLINE ===
# Watchdog - restart if unresponsive for 60 seconds
WatchdogSec=60

# Always restart on ANY exit (crash, signal, success)
Restart=always
RestartSec=5

# Progressive delay: 5s -> 10s -> 20s -> 40s -> 60s max
RestartSteps=5
RestartMaxDelaySec=60

# === LOGGING ===
StandardOutput=journal
StandardError=journal
SyslogIdentifier=lonewarrior

# === RESOURCE LIMITS ===
MemoryMax=1G
MemoryHigh=768M
CPUQuota=50%

# === SECURITY (but needs caps for iptables) ===
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA_DIR
ReadWritePaths=$LOG_DIR
ReadWritePaths=/run

# Capabilities for iptables and process control
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF

# Install secondary watchdog timer (belt AND suspenders)
cat > /etc/systemd/system/lonewarrior-watchdog.timer << 'EOF'
[Unit]
Description=LoneWarrior Health Check Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/lonewarrior-watchdog.service << 'EOF'
[Unit]
Description=LoneWarrior Health Check
After=lonewarrior.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'systemctl is-active --quiet lonewarrior || (echo "LoneWarrior down! Restarting..." && systemctl restart lonewarrior)'
EOF

echo -e "${GREEN}✓ Systemd service installed with auto-recovery${NC}"

# Install emergency stop script
echo -e "${BLUE}Installing emergency stop script...${NC}"
cat > /usr/local/bin/lw-emergency-stop << 'EMERGENCYEOF'
#!/bin/bash
# LoneWarrior Emergency Stop - Stops agent and rolls back ALL containment

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              LONEWARRIOR EMERGENCY STOP                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Stop the service and watchdog
echo -e "${YELLOW}Stopping LoneWarrior service...${NC}"
systemctl stop lonewarrior-watchdog.timer 2>/dev/null || true
systemctl stop lonewarrior 2>/dev/null || true

# Remove ALL LoneWarrior iptables chains
echo -e "${YELLOW}Removing iptables rules...${NC}"
for chain in LONEWARRIOR_BLOCK LONEWARRIOR_RATELIMIT LONEWARRIOR_CONTAIN; do
    iptables -D INPUT -j $chain 2>/dev/null || true
    iptables -D OUTPUT -j $chain 2>/dev/null || true
    iptables -D FORWARD -j $chain 2>/dev/null || true
    iptables -F $chain 2>/dev/null || true
    iptables -X $chain 2>/dev/null || true
done

# Restore SSH access
echo -e "${YELLOW}Ensuring SSH access...${NC}"
iptables -D INPUT -p tcp --dport 22 -m state --state NEW -j DROP 2>/dev/null || true

# Re-enable disabled users
if [ -f /var/lib/lonewarrior/disabled_users.txt ]; then
    echo -e "${YELLOW}Re-enabling disabled users...${NC}"
    while read -r username; do
        usermod -U "$username" 2>/dev/null && echo "  ✓ Re-enabled: $username"
        chage -E -1 "$username" 2>/dev/null || true
    done < /var/lib/lonewarrior/disabled_users.txt
    rm -f /var/lib/lonewarrior/disabled_users.txt
fi

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              EMERGENCY STOP COMPLETE                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "To restart: sudo systemctl start lonewarrior-watchdog.timer && sudo systemctl start lonewarrior"
EMERGENCYEOF
chmod +x /usr/local/bin/lw-emergency-stop
echo -e "${GREEN}✓ Emergency stop installed (use 'lw-emergency-stop')${NC}"

# Reload systemd
systemctl daemon-reload

# Enable services
echo -e "${BLUE}Enabling services...${NC}"
systemctl enable lonewarrior
systemctl enable lonewarrior-watchdog.timer
echo -e "${GREEN}✓ Services enabled${NC}"

# Summary
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗"
echo "║              INSTALLATION COMPLETE!                          ║"
echo "╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Reliability Features:${NC}"
echo "  • Auto-restart on crash (always)"
echo "  • Watchdog timer (60s timeout)"
echo "  • Secondary health check (every 1 min)"
echo "  • Progressive restart delays (5s → 60s)"
echo ""
echo -e "${BLUE}Commands:${NC}"
echo "  lw status              - Check current status"
echo "  lw detections          - View detections"
echo "  lw-emergency-stop      - Emergency stop + rollback"
echo ""
echo -e "${BLUE}Service management:${NC}"
echo "  sudo systemctl start lonewarrior"
echo "  sudo systemctl status lonewarrior"
echo "  sudo journalctl -u lonewarrior -f"
echo ""

# Ask to start
read -p "Start LoneWarrior now? [Y/n] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    systemctl start lonewarrior-watchdog.timer
    systemctl start lonewarrior
    sleep 2
    if systemctl is-active --quiet lonewarrior; then
        echo -e "${GREEN}✓ LoneWarrior is running and protected!${NC}"
    else
        echo -e "${RED}Failed to start. Check: journalctl -u lonewarrior${NC}"
    fi
else
    echo -e "${YELLOW}Service not started. Use: sudo systemctl start lonewarrior${NC}"
fi
