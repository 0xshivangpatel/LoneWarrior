# LoneWarrior VPS Deployment Guide

## Recommended Directory
```
/opt/lonewarrior
```

## Step-by-Step Deployment

### Step 1: Connect to VPS
```bash
ssh root@your-vps-ip
```

### Step 2: Install Dependencies
```bash
# Ubuntu/Debian
apt update && apt install -y python3 python3-pip python3-venv git

# CentOS/RHEL
yum install -y python3 python3-pip git
```

### Step 3: Clone Repository
```bash
cd /opt
git clone https://github.com/CoderShivang/LoneWarrior.git
cd LoneWarrior
```

### Step 4: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 5: Install Package
```bash
pip install -e .
pip install pytest pytest-cov
```

### Step 6: Run Auto Tests
```bash
# Run all tests with coverage report
python -m pytest tests/ -v --tb=short

# Or use the auto-test script
chmod +x scripts/run_tests.sh
./scripts/run_tests.sh
```

### Step 7: Install as Service (Optional)
```bash
chmod +x install.sh
sudo ./install.sh
```

### Step 8: Verify Installation
```bash
# Check service status
systemctl status lonewarrior

# Check CLI
lw status
```

## Quick One-Liner
```bash
cd /opt && git clone https://github.com/CoderShivang/LoneWarrior.git && cd LoneWarrior && python3 -m venv venv && source venv/bin/activate && pip install -e . pytest && python -m pytest tests/ -v
```
