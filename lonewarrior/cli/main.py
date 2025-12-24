"""
Command-Line Interface for LoneWarrior
"""

import os
import click
import json
import subprocess
import sqlite3
import logging
from pathlib import Path
from tabulate import tabulate
from datetime import datetime, timedelta, timezone

from lonewarrior.config.config_manager import ConfigManager
from lonewarrior.storage.database import Database
from lonewarrior.utils.validators import validate_ip_address_or_raise
from lonewarrior.storage.models import Action, ActionType, ActionStatus, Snapshot

logger = logging.getLogger(__name__)


def is_daemon_running(config: dict) -> tuple[bool, int | None]:
    """
    Check if LoneWarrior daemon is running.

    The local PID file is the primary source of truth. Systemd is only used
    as a fallback, and even then, we verify the systemd-reported PID
    actually exists and is a lonewarrior process.

    Returns:
        Tuple of (is_running, pid) where pid is None if not running
    """
    pid_file = Path(config['general']['data_dir']) / 'lonewarrior.pid'

    # Primary: Check local PID file (source of truth for this config instance)
    try:
        if pid_file.exists():
            pid = int(pid_file.read_text().strip())
            # Check if process with this PID exists and is lonewarrior
            if os.path.exists('/proc/{}'.format(pid)):
                # Verify it's actually lonewarrior by checking cmdline
                try:
                    cmdline_path = '/proc/{}/cmdline'.format(pid)
                    with open(cmdline_path, 'r') as f:
                        cmdline = f.read()
                    if 'lonewarrior' in cmdline:
                        return True, pid
                    # Process exists but not lonewarrior - stale PID file
                    return False, None
                except (PermissionError, FileNotFoundError):
                    # Can't read cmdline, but process exists
                    # Accept it as running (process exists at this PID)
                    return True, pid
            else:
                # PID file exists but process doesn't - stale PID file
                # Clean up the stale PID file
                try:
                    pid_file.unlink()
                except (PermissionError, FileNotFoundError):
                    pass
                return False, None
        # No PID file exists - continue to systemd fallback
    except PermissionError:
        # Cannot access PID file directory, try systemd fallback
        pass
    except (ValueError, FileNotFoundError):
        # Invalid PID file content, try systemd fallback
        pass

    # Fallback: Check systemd status ONLY when there's no local PID file
    # This ensures the local PID file is always the primary source of truth
    # We DO NOT use systemd to override a local PID file decision
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'lonewarrior'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip() == 'active':
            # Try to get PID from systemd
            try:
                pid_result = subprocess.run(
                    ['systemctl', 'show', '-p', 'MainPID', '--value', 'lonewarrior'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                pid_str = pid_result.stdout.strip()
                # systemd MainPID of 0 means no active process
                if pid_str and pid_str != '0':
                    pid = int(pid_str)
                    # Verify the systemd-reported PID actually exists
                    if os.path.exists('/proc/{}'.format(pid)):
                        # Also verify it's actually lonewarrior process
                        try:
                            cmdline_path = '/proc/{}/cmdline'.format(pid)
                            with open(cmdline_path, 'r') as f:
                                cmdline = f.read()
                            if 'lonewarrior' in cmdline:
                                return True, pid
                        except (PermissionError, FileNotFoundError):
                            # Can't read cmdline, but process exists
                            return True, pid
                    # Systemd reports active but PID doesn't exist - stale service state
            except (ValueError, subprocess.TimeoutExpired):
                pass
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # systemd not available or timeout
        pass

    return False, None


@click.group()
@click.pass_context
def cli(ctx):
    """LoneWarrior - Autonomous Security Agent CLI"""
    # Load config and database
    config_mgr = ConfigManager()
    config = config_mgr.load_config()
    
    db_path = Path(config['general']['data_dir']) / 'lonewarrior.db'
    db = None
    
    # Try to initialize database, but handle permission errors gracefully
    try:
        if db_path.exists() or db_path.parent.exists():
            try:
                db = Database(str(db_path))
            except (PermissionError, sqlite3.OperationalError) as e:
                logger.warning("Cannot access database at {}: {}".format(db_path, e))
                logger.warning("Most commands require root privileges. Run with sudo.")
    except PermissionError:
        logger.warning("Cannot access data directory at {}".format(db_path.parent))
        logger.warning("Most commands require root privileges. Run with sudo.")
    
    ctx.obj = {'config': config, 'db': db}


@cli.command()
@click.pass_context
def status(ctx):
    """Show current system status"""
    config = ctx.obj['config']
    db = ctx.obj['db']

    click.echo("=" * 60)
    click.echo("LoneWarrior Status")
    click.echo("=" * 60)

    # Check if daemon is running
    running, pid = is_daemon_running(config)

    if not running:
        click.echo("Status: NOT ACTIVE")
        click.echo("")
        click.echo("The LoneWarrior daemon is not running.")
        click.echo("Start it with: sudo systemctl start lonewarrior")
        click.echo("           or: python -m lonewarrior daemon")
        click.echo("=" * 60)
        return

    if db is None:
        click.echo("Status: ACTIVE (PID {} - PID verified)".format(pid if pid else "unknown"))
        click.echo("")
        click.echo("⚠️  Cannot access database (permission denied)")
        click.echo("   Run with 'sudo lw status' for detailed information")
        click.echo("=" * 60)
        return

    # Get state from database
    phase = db.get_state('phase', '0')
    phase_started = db.get_state('phase_started_at', 'unknown')
    baseline_frozen = db.get_state('baseline_frozen', 'false')
    attack_confidence = db.get_state('attack_confidence_score', '0.0')
    containment_active = db.get_state('containment_active', 'false')

    phase_names = ['Phase 0 (Instant)', 'Phase 1 (Fast)', 'Phase 2 (Expanded)', 'Phase 3 (Continuous)']

    click.echo("Status: ACTIVE (PID {})".format(pid if pid else "unknown"))
    click.echo("Current Phase: {}".format(phase_names[int(phase)]))
    click.echo("Phase Started: {}".format(phase_started))
    click.echo("Baseline Frozen: {}".format(baseline_frozen))
    click.echo("Attack Confidence: {}".format(attack_confidence))
    click.echo("Containment Active: {}".format(containment_active))
    click.echo("=" * 60)


@cli.command()
@click.option('--limit', default=20, help='Number of detections to show')
@click.pass_context
def detections(ctx, limit):
    """Show recent detections"""
    db = ctx.obj['db']
    
    if db is None:
        raise click.ClickException("Cannot access database. Run with 'sudo lw detections'")
    
    detections = db.get_detections(limit=limit)
    
    if not detections:
        click.echo("No detections found")
        return
    
    table_data = []
    for d in detections:
        table_data.append([
            d.id,
            d.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            d.detection_type,
            d.description[:50],
            f"{d.confidence_score:.1f}"
        ])
    
    click.echo("\nRecent Detections:")
    click.echo(tabulate(table_data, headers=['ID', 'Time', 'Type', 'Description', 'Score']))


@cli.command()
@click.option('--limit', default=20, help='Number of actions to show')
@click.pass_context
def actions(ctx, limit):
    """Show recent actions"""
    db = ctx.obj['db']
    
    if db is None:
        raise click.ClickException("Cannot access database. Run with 'sudo lw actions'")
    
    actions = db.get_actions(limit=limit)
    
    if not actions:
        click.echo("No actions found")
        return
    
    table_data = []
    for a in actions:
        table_data.append([
            a.id,
            a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            a.action_type,
            a.target,
            a.status
        ])
    
    click.echo("\nRecent Actions:")
    click.echo(tabulate(table_data, headers=['ID', 'Time', 'Type', 'Target', 'Status']))


@cli.group(invoke_without_command=True)
@click.option('--type', help='Filter by baseline type')
@click.pass_context
def baseline(ctx, type):
    """Baseline operations (view/freeze/unfreeze)"""
    if ctx.invoked_subcommand is not None:
        return

    # Default behavior: view baselines (backwards compatible with previous `lw baseline`)
    db = ctx.obj['db']
    if db is None:
        raise click.ClickException("Cannot access database. Run with 'sudo lw baseline'")
    
    baselines = db.get_baselines(baseline_type=type)
    if not baselines:
        click.echo("No baselines found")
        return

    table_data = []
    for b in baselines:
        table_data.append([
            b.baseline_type,
            b.key,
            b.observation_count,
            b.phase,
            b.last_seen.strftime('%Y-%m-%d %H:%M:%S')
        ])

    click.echo("\nBaselines ({} total):".format(len(baselines)))
    click.echo(tabulate(table_data[:50], headers=['Type', 'Key', 'Count', 'Phase', 'Last Seen']))
    if len(table_data) > 50:
        click.echo("\n... and {} more".format(len(table_data) - 50))


@baseline.command("freeze")
@click.option("--reason", default="manual_freeze", show_default=True)
@click.pass_context
def baseline_freeze(ctx, reason):
    """Manually freeze baseline learning"""
    db = ctx.obj["db"]
    if db is None:
        raise click.ClickException("Cannot access database. Run with 'sudo lw baseline freeze'")
    
    db.set_state("baseline_frozen", "true")
    # cooldown handled by daemon; CLI sets freeze_until best-effort
    freeze_until = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    db.set_state("freeze_until", freeze_until)
    db.add_audit_log("baseline_freeze", "user", "baseline_learning", {"reason": reason, "freeze_until": freeze_until})
    click.echo("✅ Baseline learning frozen")


@baseline.command("unfreeze")
@click.pass_context
def baseline_unfreeze(ctx):
    """Resume baseline learning"""
    db = ctx.obj["db"]
    if db is None:
        raise click.ClickException("Cannot access database. Run with 'sudo lw baseline unffreeze'")
    
    db.set_state("baseline_frozen", "false")
    db.set_state("freeze_until", "")
    db.add_audit_log("baseline_unfreeze", "user", "baseline_learning", {"resumed_at": datetime.now(timezone.utc).isoformat()})
    click.echo("✅ Baseline learning resumed")


@cli.command()
@click.argument('ip_address')
@click.pass_context
def contain(ctx, ip_address):
    """Manually trigger containment for an IP"""
    # Validate IP address to prevent command injection
    try:
        validated_ip = validate_ip_address_or_raise(ip_address)
    except ValueError as e:
        raise click.ClickException(str(e))
    config = ctx.obj["config"]
    db = ctx.obj["db"]

    if not config["actions"]["ip_block"]["enabled"]:
        click.echo("IP blocking disabled in config")
        return

    # Snapshot
    try:
        snap_res = subprocess.run(["iptables-save"], capture_output=True, text=True, timeout=10)
        rules = snap_res.stdout
    except Exception:
        rules = ""

    snapshot = Snapshot(snapshot_type="iptables", state_data={"rules": rules})
    snapshot_id = db.insert_snapshot(snapshot)

    ttl = int(config["actions"]["ip_block"]["default_ttl"])
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()

    action = Action(
        action_type=ActionType.IP_BLOCK.value,
        status=ActionStatus.EXECUTING.value,
        detection_id=None,
        target=validated_ip,
        parameters={"ttl": ttl, "expires_at": expires_at, "manual": True},
        snapshot_id=snapshot_id,
    )
    action_id = db.insert_action(action)

    try:
        # Idempotent: check then insert at top
        check = subprocess.run(["iptables", "-C", "INPUT", "-s", validated_ip, "-j", "DROP"],
                               capture_output=True, text=True, timeout=10)
        if check.returncode != 0:
            result = subprocess.run(["iptables", "-I", "INPUT", "1", "-s", validated_ip, "-j", "DROP"],
                           capture_output=True, text=True, timeout=10, check=True)
            if result.returncode != 0:
                raise RuntimeError(f"Failed to add iptables rule: {result.stderr}")
        db.update_action(action_id, ActionStatus.SUCCESS.value, result=f"Blocked {validated_ip} until {expires_at}")
        click.echo(f"✅ Blocked {validated_ip} (TTL {ttl}s)")
    except Exception as e:
        # Best-effort rollback
        try:
            if rules:
                subprocess.run(["iptables-restore"], input=rules, capture_output=True, text=True, timeout=10, check=True)
        except Exception:
            pass
        db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
        raise click.ClickException(f"Failed to block {validated_ip}: {e}")


@cli.command()
@click.argument("ip_address")
@click.pass_context
def release(ctx, ip_address):
    """Manually release containment for an IP (unblock)"""
    # Validate IP address to prevent command injection
    try:
        validated_ip = validate_ip_address_or_raise(ip_address)
    except ValueError as e:
        raise click.ClickException(str(e))
    db = ctx.obj["db"]

    try:
        snap_res = subprocess.run(["iptables-save"], capture_output=True, text=True, timeout=10)
        rules = snap_res.stdout
    except Exception:
        rules = ""

    snapshot = Snapshot(snapshot_type="iptables", state_data={"rules": rules})
    snapshot_id = db.insert_snapshot(snapshot)

    action = Action(
        action_type=ActionType.IP_UNBLOCK.value,
        status=ActionStatus.EXECUTING.value,
        detection_id=None,
        target=validated_ip,
        parameters={"manual": True},
        snapshot_id=snapshot_id,
    )
    action_id = db.insert_action(action)

    try:
        # delete all matching rules (handle duplicates) - bounded to prevent infinite loop
        max_deletes = 50
        deletes = 0
        while deletes < max_deletes:
            check = subprocess.run(["iptables", "-C", "INPUT", "-s", validated_ip, "-j", "DROP"],
                                   capture_output=True, text=True, timeout=10)
            if check.returncode != 0:
                break
            result = subprocess.run(["iptables", "-D", "INPUT", "-s", validated_ip, "-j", "DROP"],
                           capture_output=True, text=True, timeout=10, check=True)
            if result.returncode != 0:
                raise RuntimeError(f"Failed to remove iptables rule: {result.stderr}")
            deletes += 1
        
        if deletes >= max_deletes:
            raise RuntimeError(f"Too many duplicate rules for {validated_ip} (max {max_deletes})")
        
        db.update_action(action_id, ActionStatus.SUCCESS.value, result=f"Unblocked {validated_ip}")
        click.echo(f"✅ Unblocked {validated_ip}")
    except Exception as e:
        try:
            if rules:
                subprocess.run(["iptables-restore"], input=rules, capture_output=True, text=True, timeout=10, check=True)
        except Exception:
            pass
        db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
        raise click.ClickException(f"Failed to unblock {validated_ip}: {e}")


@cli.group()
def whitelist():
    """Whitelist management (writes user config)"""
    pass


@whitelist.command("add")
@click.argument("kind", type=click.Choice(["ip", "domain", "process", "user"]))
@click.argument("value")
@click.option("--config-path", default=None, help="Optional config path to write (defaults to /etc/lonewarrior/config.yaml)")
def whitelist_add(kind, value, config_path):
    """Add item to whitelist and persist to user config"""
    cm = ConfigManager(config_path=config_path)
    cfg = cm.load_config()

    mapping = {
        "ip": ("whitelists", "ips"),
        "domain": ("whitelists", "domains"),
        "process": ("whitelists", "processes"),
        "user": ("whitelists", "users"),
    }
    sect, key = mapping[kind]
    cfg.setdefault(sect, {}).setdefault(key, [])
    if value not in cfg[sect][key]:
        cfg[sect][key].append(value)
    cm.config = cfg
    cm.save_user_config(config_path)
    click.echo(f"✅ Whitelisted {kind}: {value}")


@cli.command()
@click.option("--lines", default=200, show_default=True, help="Number of lines to show")
@click.pass_context
def logs(ctx, lines):
    """Show recent agent logs (best-effort)"""
    cfg = ctx.obj["config"]
    log_path = Path(cfg["general"]["log_dir"]) / "lonewarrior.log"
    if not log_path.exists():
        raise click.ClickException(f"Log file not found: {log_path}")
    try:
        # Use PowerShell-safe read by Python
        content = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for line in content[-int(lines):]:
            click.echo(line)
    except Exception as e:
        raise click.ClickException(f"Failed to read logs: {e}")


@cli.group()
def config():
    """Configuration management"""
    pass


@config.command('set-api-key')
@click.argument('service', type=click.Choice(['abuseipdb', 'all']))
@click.argument('api_key')
@click.option('--file', '-f', type=click.Path(), help='Read API key from file')
def set_api_key(service, api_key, file=None):
    """Set external threat intel API key

    \b
    SERVICE: Which service to set key for (abuseipdb, all)
    API_KEY: The API key to set (or use -f to read from file)

    Examples:
        lw config set-api-key abuseipdb YOUR_KEY_HERE
        lw config set-api-key abuseipdb -f /path/to/key.txt
        lw config set-api-key all YOUR_KEY_FOR_ALL_SERVICES
    \b
    """
    import sys

    # Read from file if specified
    if file:
        with open(file, 'r') as f:
            api_key = f.read().strip()

    # Validate key is not empty
    if not api_key or api_key == 'your_api_key_here':
        raise click.ClickException("Please provide a valid API key")

    # Determine config paths
    config_file = Path('/etc/lonewarrior/.env')

    # Check if writable
    if not os.access(config_file.parent, os.W_OK):
        raise click.ClickException(f"Cannot write to {config_file.parent}. Run with sudo.")

    # Read existing .env file
    env_lines = []
    if config_file.exists():
        with open(config_file, 'r') as f:
            env_lines = f.readlines()

    # Remove existing key entries
    if service == 'all':
        env_lines = [line for line in env_lines if not line.startswith('ABUSEIPDB_API_KEY=')]
        env_lines.append(f"ABUSEIPDB_API_KEY={api_key}\n")
    else:
        env_lines = [line for line in env_lines if not line.startswith(f'{service.upper()}_API_KEY=' if service == 'abuseipdb' else '')]
        if service == 'abuseipdb':
            env_lines.append(f"ABUSEIPDB_API_KEY={api_key}\n")

    # Write updated .env file
    with open(config_file, 'w') as f:
        f.writelines(env_lines)

    # Set secure permissions
    os.chmod(config_file, 0o600)

    # Update defaults.yaml to enable the service
    defaults_file = Path('/etc/lonewarrior/config.yaml')
    if defaults_file.exists():
        import yaml
        from lonewarrior.config.config_manager import ConfigManager

        config_mgr = ConfigManager(config_path=str(defaults_file))
        config = config_mgr.config

        # Enable external feeds and the specific service
        if not config.get('threat_intel', {}).get('external_feeds', {}).get('enabled', False):
            click.echo("⚠️  External threat intel feeds are disabled in config")
            click.echo("Enabling external feeds...")

        config.setdefault('threat_intel', {})
        config['threat_intel'].setdefault('external_feeds', {})
        config['threat_intel']['external_feeds']['enabled'] = True

        if service in ['abuseipdb', 'all']:
            config['threat_intel']['external_feeds'].setdefault('abuseipdb', {})
            config['threat_intel']['external_feeds']['abuseipdb']['enabled'] = True

        # Write updated config
        with open(defaults_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)

    click.echo(f"✅ API key set for {service}")
    click.echo(f"🔒 Saved to: {config_file}")
    click.echo("")
    click.echo("Restart LoneWarrior to apply changes:")
    click.echo("  systemctl restart lonewarrior")


@config.command('show-api-keys')
def show_api_keys():
    """Show configured API keys (masked for security)"""
    config_file = Path('/etc/lonewarrior/.env')

    if not config_file.exists():
        click.echo("No API keys configured")
        return

    with open(config_file, 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                # Mask the key value
                if len(value) > 8:
                    masked = value[:4] + '*' * (len(value) - 8) + value[-4:]
                else:
                    masked = '*' * len(value)
                click.echo(f"{key}={masked}")


@cli.command()
@click.argument('action_id', type=int)
@click.argument('feedback', type=click.Choice(['correct', 'false_positive', 'too_aggressive', 'missed_threat']))
@click.pass_context
def feedback(ctx, action_id, feedback):
    """Provide feedback on an action"""
    db = ctx.obj['db']
    
    if db is None:
        raise click.ClickException("Cannot access database. Run with 'sudo lw feedback <id> <feedback>'")
    
    db.add_action_feedback(action_id, feedback)
    click.echo("✅ Feedback '{}' recorded for action {}".format(feedback, action_id))


@cli.command()
@click.pass_context
def emergency_stop(ctx):
    """Emergency stop - halt all actions"""
    config = ctx.obj['config']
    stop_file = Path(config['emergency']['stop_file'])
    
    stop_file.parent.mkdir(parents=True, exist_ok=True)
    stop_file.touch()
    
    click.echo("🚨 EMERGENCY STOP activated")
    click.echo(f"Created: {stop_file}")
    click.echo("The daemon will  halt all actions and begin rollback")


@cli.command()
@click.option('--force', is_flag=True, help='Skip confirmation prompt')
@click.option('--keep-audit', is_flag=True, default=True, help='Keep audit log (default: yes)')
@click.pass_context
def reset(ctx, force, keep_audit):
    """Reset LoneWarrior to a clean slate - restart baseline learning from scratch
    
    This will:
    - Clear all learned baselines
    - Clear all detections
    - Clear all actions
    - Reset phase to initial state
    - Restart the learning process
    """
    import os
    
    # Check for root privileges (required to write to the database)
    if os.geteuid() != 0:
        raise click.ClickException("Reset requires root privileges. Run with: sudo lw reset")
    
    db = ctx.obj['db']
    if db is None:
        raise click.ClickException("Cannot access database. Run with: sudo lw reset")
    
    if not force:
        click.echo("⚠️  WARNING: This will delete ALL learned baselines and detections!")
        click.echo("   LoneWarrior will restart learning from scratch.")
        click.echo("")
        if not click.confirm("Are you sure you want to reset?"):
            click.echo("Reset cancelled.")
            return
    
    click.echo("🔄 Resetting LoneWarrior...")
    
    # Stop the service first (if running)
    try:
        import subprocess
        subprocess.run(['systemctl', 'stop', 'lonewarrior'], capture_output=True, timeout=10)
        click.echo("   Stopped lonewarrior service")
    except Exception:
        pass  # May not be running or not on systemd
    
    # Clear the database
    cleared = db.reset_all(keep_audit_log=keep_audit)
    
    click.echo("")
    click.echo("Cleared:")
    for table, count in cleared.items():
        if count > 0:
            click.echo("   • {}: {} records".format(table, count))
    
    click.echo("")
    click.echo("✅ Reset complete!")
    click.echo("")
    click.echo("To restart learning, run:")
    click.echo("   sudo systemctl start lonewarrior")
    click.echo("")
    click.echo("LoneWarrior will now learn your system from scratch.")


if __name__ == '__main__':
    cli()
