#!/bin/bash
# ============================================================================
# LoneWarrior — One-Shot Installer
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/0xshivangpatel/LoneWarrior/main/get-lonewarrior.sh | sudo bash
#
# Or with options:
#   curl -sSL ... | sudo bash -s -- --no-start --skip-setup
#
# What this does:
#   1. Installs system dependencies (python3, iptables, etc.)
#   2. Clones the repo (or pulls if already installed)
#   3. Creates a Python venv and installs the package
#   4. Sets up systemd service with auto-restart + watchdog
#   5. Optionally runs interactive setup (alerting, API keys)
#   6. Starts the service
#
# Supports: Ubuntu/Debian, RHEL/CentOS/Rocky/Fedora, Arch
# ============================================================================

set -euo pipefail

# --- Configuration -----------------------------------------------------------
REPO_URL="https://github.com/0xshivangpatel/LoneWarrior.git"
INSTALL_DIR="/opt/lonewarrior"
VENV_DIR="$INSTALL_DIR/venv"
CONFIG_DIR="/etc/lonewarrior"
DATA_DIR="/var/lib/lonewarrior"
LOG_DIR="/var/log/lonewarrior"
VERSION="1.1.0"

# --- CLI flags ---------------------------------------------------------------
NO_START=false
SKIP_SETUP=false
UNINSTALL=false

for arg in "$@"; do
    case $arg in
        --no-start)    NO_START=true ;;
        --skip-setup)  SKIP_SETUP=true ;;
        --uninstall)   UNINSTALL=true ;;
        --help|-h)
            echo "Usage: get-lonewarrior.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-start     Install but don't start the service"
            echo "  --skip-setup   Skip interactive alerting setup"
            echo "  --uninstall    Remove LoneWarrior completely"
            echo "  --help         Show this message"
            exit 0
            ;;
    esac
done

# --- Colors ------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; }

banner() {
    echo ""
    echo -e "${BOLD}"
    echo "  _                   __        __              _            "
    echo " | |    ___  _ __   __\ \      / /_ _ _ __ _ __(_) ___  _ __ "
    echo " | |   / _ \| '_ \ / _ \ \ /\ / / _\` | '__| '__| |/ _ \| '__|"
    echo " | |__| (_) | | | |  __/\ V  V / (_| | |  | |  | | (_) | |   "
    echo " |_____\___/|_| |_|\___| \_/\_/ \__,_|_|  |_|  |_|\___/|_|   "
    echo ""
    echo "  Autonomous Security Agent — v${VERSION}"
    echo -e "${NC}"
    echo ""
}

# --- Uninstall ---------------------------------------------------------------
if [ "$UNINSTALL" = true ]; then
    banner
    warn "Uninstalling LoneWarrior..."

    systemctl stop lonewarrior 2>/dev/null || true
    systemctl stop lonewarrior-watchdog.timer 2>/dev/null || true
    systemctl disable lonewarrior 2>/dev/null || true
    systemctl disable lonewarrior-watchdog.timer 2>/dev/null || true

    rm -f /etc/systemd/system/lonewarrior.service
    rm -f /etc/systemd/system/lonewarrior-watchdog.service
    rm -f /etc/systemd/system/lonewarrior-watchdog.timer
    systemctl daemon-reload 2>/dev/null || true

    rm -f /usr/local/bin/lw
    rm -f /usr/local/bin/lw-emergency-stop
    rm -rf "$INSTALL_DIR"

    success "LoneWarrior removed."
    info "Data preserved in $DATA_DIR and $LOG_DIR"
    info "Config preserved in $CONFIG_DIR"
    info "To remove everything: rm -rf $DATA_DIR $LOG_DIR $CONFIG_DIR"
    exit 0
fi

# --- Preflight checks --------------------------------------------------------
banner

if [ "$(id -u)" -ne 0 ]; then
    error "This installer must be run as root."
    echo "  Run: curl -sSL <url> | sudo bash"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS="unknown"
fi
info "Detected OS: $OS"

# --- Step 1: System dependencies --------------------------------------------
info "Installing system dependencies..."

if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq > /dev/null 2>&1
    apt-get install -y -qq python3 python3-pip python3-venv git iptables conntrack > /dev/null 2>&1
elif [ "$OS" = "centos" ] || [ "$OS" = "rhel" ] || [ "$OS" = "fedora" ] || [ "$OS" = "rocky" ] || [ "$OS" = "almalinux" ]; then
    if command -v dnf &> /dev/null; then
        dnf install -y -q python3 python3-pip git iptables conntrack-tools > /dev/null 2>&1
    else
        yum install -y -q python3 python3-pip git iptables conntrack-tools > /dev/null 2>&1
    fi
elif [ "$OS" = "arch" ]; then
    pacman -Sy --noconfirm --quiet python python-pip git iptables conntrack-tools > /dev/null 2>&1
else
    warn "Unknown OS '$OS'. Assuming dependencies are installed."
fi
success "System dependencies ready"

# --- Step 2: Clone or update the repo ----------------------------------------
if [ -d "$INSTALL_DIR/.git" ]; then
    info "Updating existing installation..."
    cd "$INSTALL_DIR"
    git fetch --quiet origin
    git reset --hard origin/main --quiet 2>/dev/null || git reset --hard origin/master --quiet
    success "Updated to latest version"
else
    info "Downloading LoneWarrior..."
    rm -rf "$INSTALL_DIR"
    git clone --quiet --depth 1 "$REPO_URL" "$INSTALL_DIR"
    success "Downloaded to $INSTALL_DIR"
fi

# --- Step 3: Python venv + install ------------------------------------------
info "Setting up Python environment..."

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --upgrade pip -q > /dev/null 2>&1
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q > /dev/null 2>&1
"$VENV_DIR/bin/pip" install -e "$INSTALL_DIR" -q > /dev/null 2>&1

# Verify
"$VENV_DIR/bin/python" -c "import lonewarrior" 2>/dev/null || {
    error "Installation failed — lonewarrior module not importable"
    exit 1
}
success "Python package installed"

# --- Step 4: Create directories + config -------------------------------------
mkdir -p "$DATA_DIR" "$LOG_DIR" "$CONFIG_DIR" "$DATA_DIR/snapshots" "$DATA_DIR/backups"
chmod 700 "$DATA_DIR"
chmod 750 "$LOG_DIR"

if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    cp "$INSTALL_DIR/lonewarrior/config/defaults.yaml" "$CONFIG_DIR/config.yaml"
    success "Default config installed at $CONFIG_DIR/config.yaml"
else
    success "Existing config preserved at $CONFIG_DIR/config.yaml"
fi

# --- Step 5: CLI wrapper -----------------------------------------------------
cat > /usr/local/bin/lw << 'EOF'
#!/bin/bash
/opt/lonewarrior/venv/bin/python -m lonewarrior.cli.main "$@"
EOF
chmod +x /usr/local/bin/lw

# Emergency stop
cat > /usr/local/bin/lw-emergency-stop << 'ESEOF'
#!/bin/bash
set -e
echo "Stopping LoneWarrior..."
systemctl stop lonewarrior-watchdog.timer 2>/dev/null || true
systemctl stop lonewarrior 2>/dev/null || true

echo "Removing iptables rules..."
for chain in LONEWARRIOR_BLOCK LONEWARRIOR_RATELIMIT LONEWARRIOR_CONTAIN; do
    iptables -D INPUT -j $chain 2>/dev/null || true
    iptables -D OUTPUT -j $chain 2>/dev/null || true
    iptables -F $chain 2>/dev/null || true
    iptables -X $chain 2>/dev/null || true
done

echo "Re-enabling any disabled users..."
if [ -f /var/lib/lonewarrior/disabled_users.txt ]; then
    while read -r u; do usermod -U "$u" 2>/dev/null; done < /var/lib/lonewarrior/disabled_users.txt
    rm -f /var/lib/lonewarrior/disabled_users.txt
fi

echo "Emergency stop complete."
echo "Restart: sudo systemctl start lonewarrior"
ESEOF
chmod +x /usr/local/bin/lw-emergency-stop

success "CLI installed: lw, lw-emergency-stop"

# --- Step 6: systemd service -------------------------------------------------
cat > /etc/systemd/system/lonewarrior.service << SVCEOF
[Unit]
Description=LoneWarrior Autonomous Security Agent
Documentation=https://github.com/0xshivangpatel/LoneWarrior
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python -m lonewarrior --config $CONFIG_DIR/config.yaml
Restart=always
RestartSec=5
WatchdogSec=60
StandardOutput=journal
StandardError=journal
SyslogIdentifier=lonewarrior

MemoryMax=1G
MemoryHigh=768M
CPUQuota=50%

ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA_DIR $LOG_DIR /run
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
SVCEOF

# Watchdog timer (secondary health check)
cat > /etc/systemd/system/lonewarrior-watchdog.timer << 'WTEOF'
[Unit]
Description=LoneWarrior Health Check Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
WTEOF

cat > /etc/systemd/system/lonewarrior-watchdog.service << 'WSEOF'
[Unit]
Description=LoneWarrior Health Check
After=lonewarrior.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'systemctl is-active --quiet lonewarrior || systemctl restart lonewarrior'
WSEOF

systemctl daemon-reload
systemctl enable lonewarrior > /dev/null 2>&1
systemctl enable lonewarrior-watchdog.timer > /dev/null 2>&1
success "Systemd service installed (auto-restart + watchdog)"

# --- Step 7: Interactive setup (alerting) ------------------------------------
setup_alerting() {
    echo ""
    echo -e "${BOLD}--- Alerting Setup ---${NC}"
    echo "LoneWarrior can notify you when threats are detected."
    echo ""

    local CONFIG_FILE="$CONFIG_DIR/config.yaml"
    local CHANGED=false

    # --- Webhook (Slack/Discord/Teams) ---
    read -p "Set up webhook notifications? (Slack/Discord/Teams) [y/N] " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "  Webhook URL: " WEBHOOK_URL
        if [ -n "$WEBHOOK_URL" ]; then
            # Use Python to safely update YAML
            "$VENV_DIR/bin/python" - "$CONFIG_FILE" "$WEBHOOK_URL" << 'PYEOF'
import sys, yaml
config_path, webhook_url = sys.argv[1], sys.argv[2]
with open(config_path) as f:
    cfg = yaml.safe_load(f) or {}
cfg.setdefault("alerting", {})
cfg["alerting"]["enabled"] = True
cfg["alerting"].setdefault("webhook", {})
cfg["alerting"]["webhook"]["enabled"] = True
cfg["alerting"]["webhook"]["webhook_url"] = webhook_url
with open(config_path, "w") as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
PYEOF
            success "Webhook configured"
            CHANGED=true
        fi
    fi

    # --- Email ---
    read -p "Set up email notifications? [y/N] " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "  SMTP host (e.g. smtp.gmail.com): " SMTP_HOST
        read -p "  SMTP port [587]: " SMTP_PORT
        SMTP_PORT=${SMTP_PORT:-587}
        read -p "  SMTP username (your email): " SMTP_USER
        read -s -p "  SMTP password: " SMTP_PASS
        echo ""
        read -p "  Send alerts to (email): " TO_EMAIL

        if [ -n "$SMTP_HOST" ] && [ -n "$TO_EMAIL" ]; then
            "$VENV_DIR/bin/python" - "$CONFIG_FILE" "$SMTP_HOST" "$SMTP_PORT" "$SMTP_USER" "$SMTP_PASS" "$TO_EMAIL" << 'PYEOF'
import sys, yaml
config_path = sys.argv[1]
smtp_host, smtp_port, smtp_user, smtp_pass, to_email = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
with open(config_path) as f:
    cfg = yaml.safe_load(f) or {}
cfg.setdefault("alerting", {})
cfg["alerting"]["enabled"] = True
cfg["alerting"].setdefault("email", {})
cfg["alerting"]["email"]["enabled"] = True
cfg["alerting"]["email"]["smtp_host"] = smtp_host
cfg["alerting"]["email"]["smtp_port"] = int(smtp_port)
cfg["alerting"]["email"]["smtp_user"] = smtp_user
cfg["alerting"]["email"]["smtp_password"] = smtp_pass
cfg["alerting"]["email"]["from_address"] = smtp_user
cfg["alerting"]["email"]["to_addresses"] = [to_email]
cfg["alerting"]["email"]["use_ssl"] = (int(smtp_port) == 465)
with open(config_path, "w") as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
PYEOF
            # Secure the config file since it now has SMTP credentials
            chmod 600 "$CONFIG_FILE"
            success "Email configured"
            CHANGED=true
        fi
    fi

    # --- AbuseIPDB API key (optional) ---
    read -p "Do you have an AbuseIPDB API key? (free at abuseipdb.com) [y/N] " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "  API key: " ABUSE_KEY
        if [ -n "$ABUSE_KEY" ]; then
            "$VENV_DIR/bin/python" - "$CONFIG_FILE" "$ABUSE_KEY" << 'PYEOF'
import sys, yaml
config_path, api_key = sys.argv[1], sys.argv[2]
with open(config_path) as f:
    cfg = yaml.safe_load(f) or {}
cfg.setdefault("threat_intel", {}).setdefault("external_feeds", {})
cfg["threat_intel"]["external_feeds"]["enabled"] = True
cfg["threat_intel"]["external_feeds"].setdefault("abuseipdb", {})
cfg["threat_intel"]["external_feeds"]["abuseipdb"]["enabled"] = True
cfg["threat_intel"]["external_feeds"]["abuseipdb"]["api_key"] = api_key
with open(config_path, "w") as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
PYEOF
            # Install requests for threat intel feeds
            "$VENV_DIR/bin/pip" install requests -q > /dev/null 2>&1
            success "AbuseIPDB configured"
            CHANGED=true
        fi
    fi

    if [ "$CHANGED" = false ]; then
        info "No alerting configured. You can set it up later:"
        echo "  Edit $CONFIG_DIR/config.yaml"
        echo "  Then: sudo systemctl restart lonewarrior"
    fi
}

if [ "$SKIP_SETUP" = false ] && [ -t 0 ]; then
    # Only run interactive setup if stdin is a terminal
    echo ""
    read -p "$(echo -e "${BOLD}Run quick setup? (alerting, API keys) [Y/n]${NC} ")" -r
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        setup_alerting
    fi
fi

# --- Step 8: Start the service -----------------------------------------------
echo ""
echo -e "${BOLD}============================================================${NC}"

if [ "$NO_START" = true ]; then
    success "Installation complete!"
    info "Start manually: sudo systemctl start lonewarrior"
else
    info "Starting LoneWarrior..."
    systemctl start lonewarrior-watchdog.timer
    systemctl start lonewarrior
    sleep 2

    if systemctl is-active --quiet lonewarrior; then
        success "LoneWarrior is running!"
    else
        warn "Service started but may still be initializing."
        info "Check: sudo journalctl -u lonewarrior -f"
    fi
fi

echo ""
echo -e "${BOLD}Quick Reference:${NC}"
echo "  lw status            Show current status"
echo "  lw detections        View recent detections"
echo "  lw actions           View actions taken"
echo "  lw baseline          View learned baselines"
echo "  lw-emergency-stop    Emergency stop + rollback"
echo ""
echo -e "${BOLD}Logs:${NC}"
echo "  sudo journalctl -u lonewarrior -f"
echo ""
echo -e "${BOLD}Config:${NC}"
echo "  $CONFIG_DIR/config.yaml"
echo ""
echo -e "${BOLD}Update:${NC}"
echo "  Re-run this installer — it will pull the latest version."
echo ""
success "Done. LoneWarrior is protecting this server."
