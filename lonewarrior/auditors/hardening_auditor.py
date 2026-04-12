"""
Hardening Auditor - Server hardening configuration audit

Runs on first install (after a 30-second boot delay) and periodically
to check common server misconfigurations. Checks SSH config, firewall
status, open ports, file permissions, system updates, user accounts,
TLS certificate expiry, and kernel security settings.
"""

import logging
import json
import os
import re
import glob
import subprocess
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

from lonewarrior.storage.database import Database
from lonewarrior.core.event_bus import EventBus, EventPriority


logger = logging.getLogger(__name__)


class HardeningAuditor:
    """
    Audits server hardening configuration and publishes findings.

    Checks SSH, firewall, open ports, file permissions, system updates,
    user accounts, TLS certificates, and kernel security parameters.

    Constructor args follow the codebase convention (config, database, event_bus).
    """

    # Ports that are expected to be open by default
    DEFAULT_ALLOWED_PORTS = {22, 80, 443}

    # Services that should listen on localhost only, not 0.0.0.0
    LOCALHOST_ONLY_PORTS = {
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB',
    }

    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus):
        self.config = config
        self.db = database
        self.event_bus = event_bus

        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Configurable settings
        hardening_cfg = config.get('hardening', {})
        self.audit_interval = hardening_cfg.get('audit_interval', 86400)  # 24 hours
        self.initial_delay = hardening_cfg.get('initial_delay', 30)  # seconds
        self.allowed_ports = set(
            hardening_cfg.get('allowed_ports', [])
        ) | self.DEFAULT_ALLOWED_PORTS
        self.cert_expiry_warn_days = hardening_cfg.get('cert_expiry_warn_days', 30)

        self.logger = logging.getLogger('lonewarrior.auditors.HardeningAuditor')

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Start the audit thread."""
        if self.running:
            self.logger.warning("Hardening auditor already running")
            return

        self.running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._audit_loop, daemon=True)
        self._thread.start()
        self.logger.info(
            f"Hardening auditor started (interval: {self.audit_interval}s, "
            f"initial delay: {self.initial_delay}s)"
        )

    def stop(self):
        """Stop the audit thread."""
        if not self.running:
            return

        self.running = False
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=15)

        self.logger.info("Hardening auditor stopped")

    # ------------------------------------------------------------------
    # Audit loop
    # ------------------------------------------------------------------

    def _audit_loop(self):
        """Background loop: initial delay, then periodic audits."""
        self.logger.info(
            f"Waiting {self.initial_delay}s before first hardening audit..."
        )
        if self._stop_event.wait(self.initial_delay):
            return  # stopped during initial delay

        while self.running:
            try:
                findings = self.run_audit()
                self._publish_results(findings)
                self._store_results(findings)
                self._log_findings(findings)
            except Exception as exc:
                self.logger.error(
                    f"Error during hardening audit: {exc}", exc_info=True
                )

            # Wait for next cycle (interruptible)
            if self._stop_event.wait(self.audit_interval):
                break

    # ------------------------------------------------------------------
    # Public audit entry-point
    # ------------------------------------------------------------------

    def run_audit(self) -> List[Dict[str, Any]]:
        """
        Run all hardening checks and return a list of findings.

        Each finding is a dict with keys:
            category, severity, title, description, remediation, passed
        """
        self.logger.info("Starting hardening audit...")
        start_time = time.monotonic()

        findings: List[Dict[str, Any]] = []

        checks = [
            self._check_ssh_config,
            self._check_firewall,
            self._check_open_ports,
            self._check_file_permissions,
            self._check_system_updates,
            self._check_user_accounts,
            self._check_tls_certificates,
            self._check_kernel_security,
        ]

        for check_fn in checks:
            try:
                results = check_fn()
                findings.extend(results)
            except Exception as exc:
                self.logger.error(
                    f"Check {check_fn.__name__} failed: {exc}", exc_info=True
                )
                findings.append(self._make_finding(
                    category=check_fn.__name__.replace('_check_', ''),
                    severity='medium',
                    title=f'Audit check failed: {check_fn.__name__}',
                    description=f'The check raised an exception: {exc}',
                    remediation='Investigate the error and ensure required tools are installed.',
                    passed=False,
                ))

        elapsed = time.monotonic() - start_time
        self.logger.info(
            f"Hardening audit complete: {len(findings)} findings in {elapsed:.1f}s"
        )
        return findings

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_ssh_config(self) -> List[Dict[str, Any]]:
        """Check /etc/ssh/sshd_config for insecure settings."""
        findings: List[Dict[str, Any]] = []
        sshd_config_path = '/etc/ssh/sshd_config'

        try:
            with open(sshd_config_path, 'r') as fh:
                content = fh.read()
        except FileNotFoundError:
            findings.append(self._make_finding(
                category='ssh',
                severity='info',
                title='sshd_config not found',
                description=f'{sshd_config_path} does not exist. SSH may not be installed.',
                remediation='No action needed if SSH is not required on this server.',
                passed=True,
            ))
            return findings
        except PermissionError:
            findings.append(self._make_finding(
                category='ssh',
                severity='medium',
                title='Cannot read sshd_config',
                description=f'Permission denied reading {sshd_config_path}.',
                remediation='Run the auditor with sufficient privileges to read SSH configuration.',
                passed=False,
            ))
            return findings

        directives = self._parse_sshd_config(content)

        # PermitRootLogin
        value = directives.get('permitrootlogin', 'prohibit-password')
        if value.lower() not in ('no',):
            findings.append(self._make_finding(
                category='ssh',
                severity='critical',
                title='SSH root login is permitted',
                description=f'PermitRootLogin is set to "{value}". Direct root login should be disabled.',
                remediation='Set "PermitRootLogin no" in /etc/ssh/sshd_config and restart sshd.',
                passed=False,
            ))
        else:
            findings.append(self._make_finding(
                category='ssh',
                severity='info',
                title='SSH root login is disabled',
                description='PermitRootLogin is set to "no".',
                remediation='No action needed.',
                passed=True,
            ))

        # PasswordAuthentication
        value = directives.get('passwordauthentication', 'yes')
        if value.lower() != 'no':
            findings.append(self._make_finding(
                category='ssh',
                severity='high',
                title='SSH password authentication is enabled',
                description=f'PasswordAuthentication is "{value}". Key-based auth is preferred.',
                remediation='Set "PasswordAuthentication no" in /etc/ssh/sshd_config and restart sshd.',
                passed=False,
            ))
        else:
            findings.append(self._make_finding(
                category='ssh',
                severity='info',
                title='SSH password authentication is disabled',
                description='PasswordAuthentication is set to "no".',
                remediation='No action needed.',
                passed=True,
            ))

        # MaxAuthTries
        value = directives.get('maxauthtries', '6')
        try:
            max_tries = int(value)
        except ValueError:
            max_tries = 6
        if max_tries > 3:
            findings.append(self._make_finding(
                category='ssh',
                severity='medium',
                title='SSH MaxAuthTries is too high',
                description=f'MaxAuthTries is {max_tries}. Should be <= 3 to limit brute-force.',
                remediation='Set "MaxAuthTries 3" in /etc/ssh/sshd_config and restart sshd.',
                passed=False,
            ))
        else:
            findings.append(self._make_finding(
                category='ssh',
                severity='info',
                title='SSH MaxAuthTries is acceptable',
                description=f'MaxAuthTries is {max_tries}.',
                remediation='No action needed.',
                passed=True,
            ))

        # Protocol (only relevant on very old sshd; modern versions dropped v1)
        value = directives.get('protocol', '2')
        if value != '2':
            findings.append(self._make_finding(
                category='ssh',
                severity='critical',
                title='SSH Protocol 1 may be enabled',
                description=f'Protocol is set to "{value}". Only Protocol 2 should be used.',
                remediation='Set "Protocol 2" in /etc/ssh/sshd_config and restart sshd.',
                passed=False,
            ))
        else:
            findings.append(self._make_finding(
                category='ssh',
                severity='info',
                title='SSH Protocol 2 is enforced',
                description='Protocol is set to "2".',
                remediation='No action needed.',
                passed=True,
            ))

        # X11Forwarding
        value = directives.get('x11forwarding', 'no')
        if value.lower() != 'no':
            findings.append(self._make_finding(
                category='ssh',
                severity='medium',
                title='SSH X11 forwarding is enabled',
                description='X11Forwarding is enabled, which can expose the X11 display.',
                remediation='Set "X11Forwarding no" in /etc/ssh/sshd_config and restart sshd.',
                passed=False,
            ))
        else:
            findings.append(self._make_finding(
                category='ssh',
                severity='info',
                title='SSH X11 forwarding is disabled',
                description='X11Forwarding is set to "no".',
                remediation='No action needed.',
                passed=True,
            ))

        # PermitEmptyPasswords
        value = directives.get('permitemptypasswords', 'no')
        if value.lower() != 'no':
            findings.append(self._make_finding(
                category='ssh',
                severity='critical',
                title='SSH permits empty passwords',
                description='PermitEmptyPasswords is enabled. This is extremely dangerous.',
                remediation='Set "PermitEmptyPasswords no" in /etc/ssh/sshd_config and restart sshd.',
                passed=False,
            ))
        else:
            findings.append(self._make_finding(
                category='ssh',
                severity='info',
                title='SSH empty passwords are denied',
                description='PermitEmptyPasswords is set to "no".',
                remediation='No action needed.',
                passed=True,
            ))

        return findings

    def _check_firewall(self) -> List[Dict[str, Any]]:
        """Check whether a firewall (iptables/ufw/firewalld) is active."""
        findings: List[Dict[str, Any]] = []
        firewall_active = False

        # Check ufw
        try:
            result = subprocess.run(
                ['ufw', 'status'],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and 'active' in result.stdout.lower():
                firewall_active = True
                findings.append(self._make_finding(
                    category='firewall',
                    severity='info',
                    title='UFW firewall is active',
                    description='Uncomplicated Firewall (ufw) is running and active.',
                    remediation='No action needed.',
                    passed=True,
                ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check firewalld
        if not firewall_active:
            try:
                result = subprocess.run(
                    ['firewall-cmd', '--state'],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and 'running' in result.stdout.lower():
                    firewall_active = True
                    findings.append(self._make_finding(
                        category='firewall',
                        severity='info',
                        title='firewalld is active',
                        description='firewalld is running.',
                        remediation='No action needed.',
                        passed=True,
                    ))
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Check iptables rules (if no higher-level tool is active)
        if not firewall_active:
            try:
                result = subprocess.run(
                    ['iptables', '-L', '-n'],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    # Count non-default rules (lines beyond headers)
                    lines = [
                        l for l in result.stdout.strip().splitlines()
                        if l and not l.startswith('Chain') and not l.startswith('target')
                    ]
                    if lines:
                        firewall_active = True
                        findings.append(self._make_finding(
                            category='firewall',
                            severity='info',
                            title='iptables rules are present',
                            description=f'iptables has {len(lines)} active rules.',
                            remediation='No action needed.',
                            passed=True,
                        ))
            except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
                pass

        if not firewall_active:
            findings.append(self._make_finding(
                category='firewall',
                severity='critical',
                title='No active firewall detected',
                description=(
                    'No running firewall was found (checked ufw, firewalld, iptables). '
                    'The server may be fully exposed.'
                ),
                remediation=(
                    'Install and enable a firewall. For Ubuntu/Debian: '
                    '"apt install ufw && ufw enable". '
                    'For RHEL/CentOS: "yum install firewalld && systemctl enable --now firewalld".'
                ),
                passed=False,
            ))

        return findings

    def _check_open_ports(self) -> List[Dict[str, Any]]:
        """Check listening ports via ss and flag unexpected ones."""
        findings: List[Dict[str, Any]] = []

        try:
            result = subprocess.run(
                ['ss', '-tlnp'],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                findings.append(self._make_finding(
                    category='ports',
                    severity='medium',
                    title='Could not list open ports',
                    description=f'ss command failed: {result.stderr.strip()}',
                    remediation='Ensure the iproute2 package is installed.',
                    passed=False,
                ))
                return findings
        except FileNotFoundError:
            findings.append(self._make_finding(
                category='ports',
                severity='medium',
                title='ss command not found',
                description='The ss utility is not available on this system.',
                remediation='Install the iproute2 package.',
                passed=False,
            ))
            return findings
        except subprocess.TimeoutExpired:
            findings.append(self._make_finding(
                category='ports',
                severity='medium',
                title='ss command timed out',
                description='The ss command timed out while listing listening ports.',
                remediation='Investigate system load or process issues.',
                passed=False,
            ))
            return findings

        open_ports = self._parse_ss_output(result.stdout)
        unexpected_ports = []
        localhost_violations = []

        for entry in open_ports:
            port = entry['port']
            addr = entry['address']

            # Check for unexpected open ports
            if port not in self.allowed_ports:
                unexpected_ports.append(entry)

            # Check for services that should be localhost-only
            if port in self.LOCALHOST_ONLY_PORTS and addr in ('0.0.0.0', '*', '::'):
                localhost_violations.append(entry)

        if unexpected_ports:
            port_list = ', '.join(
                f"{e['port']}/{e.get('process', 'unknown')}" for e in unexpected_ports
            )
            findings.append(self._make_finding(
                category='ports',
                severity='high',
                title='Unexpected ports are open',
                description=(
                    f'The following ports are listening but not in the allowed list: '
                    f'{port_list}. Allowed ports: {sorted(self.allowed_ports)}.'
                ),
                remediation=(
                    'Close unnecessary ports or add them to the hardening.allowed_ports '
                    'configuration if they are intentional.'
                ),
                passed=False,
            ))
        else:
            findings.append(self._make_finding(
                category='ports',
                severity='info',
                title='No unexpected open ports',
                description='All listening ports are in the allowed list.',
                remediation='No action needed.',
                passed=True,
            ))

        for entry in localhost_violations:
            svc_name = self.LOCALHOST_ONLY_PORTS.get(entry['port'], 'unknown service')
            findings.append(self._make_finding(
                category='ports',
                severity='high',
                title=f'{svc_name} is listening on all interfaces',
                description=(
                    f'{svc_name} (port {entry["port"]}) is bound to {entry["address"]} '
                    f'instead of 127.0.0.1. This exposes the database to the network.'
                ),
                remediation=(
                    f'Configure {svc_name} to bind to 127.0.0.1 only. '
                    f'Check the service configuration file and restart the service.'
                ),
                passed=False,
            ))

        return findings

    def _check_file_permissions(self) -> List[Dict[str, Any]]:
        """Check permissions on critical system files and directories."""
        findings: List[Dict[str, Any]] = []

        # /etc/passwd should be 644
        findings.extend(self._check_file_mode(
            '/etc/passwd', {0o644}, 'permissions',
            'critical system file', '644',
        ))

        # /etc/shadow should be 640 or 600
        findings.extend(self._check_file_mode(
            '/etc/shadow', {0o640, 0o600}, 'permissions',
            'password shadow file', '640 or 600',
        ))

        # /etc/ssh/ directory should be 700 or 755
        findings.extend(self._check_file_mode(
            '/etc/ssh', {0o700, 0o755}, 'permissions',
            'SSH configuration directory', '700 or 755',
        ))

        # Home directories should not be world-readable
        findings.extend(self._check_home_directories())

        # World-writable files in /etc
        findings.extend(self._check_world_writable_etc())

        return findings

    def _check_system_updates(self) -> List[Dict[str, Any]]:
        """Check for unattended-upgrades and last update time."""
        findings: List[Dict[str, Any]] = []

        # Check unattended-upgrades (Debian/Ubuntu)
        try:
            result = subprocess.run(
                ['dpkg', '-s', 'unattended-upgrades'],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and 'Status: install ok installed' in result.stdout:
                findings.append(self._make_finding(
                    category='updates',
                    severity='info',
                    title='unattended-upgrades is installed',
                    description='Automatic security updates are configured via unattended-upgrades.',
                    remediation='No action needed.',
                    passed=True,
                ))
            else:
                findings.append(self._make_finding(
                    category='updates',
                    severity='high',
                    title='unattended-upgrades is not installed',
                    description=(
                        'Automatic security updates are not configured. '
                        'The system may miss critical patches.'
                    ),
                    remediation=(
                        'Install unattended-upgrades: '
                        '"apt install unattended-upgrades && '
                        'dpkg-reconfigure -plow unattended-upgrades".'
                    ),
                    passed=False,
                ))
        except FileNotFoundError:
            # Not a Debian-based system
            findings.append(self._make_finding(
                category='updates',
                severity='info',
                title='Not a Debian-based system',
                description='dpkg not found; skipping unattended-upgrades check.',
                remediation='Ensure automatic updates are configured for your distribution.',
                passed=True,
            ))
        except subprocess.TimeoutExpired:
            pass

        # Check last update time via apt history or stamp file
        stamp_path = '/var/lib/apt/periodic/update-success-stamp'
        try:
            mtime = os.path.getmtime(stamp_path)
            last_update = datetime.fromtimestamp(mtime, tz=timezone.utc)
            age = datetime.now(timezone.utc) - last_update
            if age > timedelta(days=30):
                findings.append(self._make_finding(
                    category='updates',
                    severity='high',
                    title='System has not been updated recently',
                    description=(
                        f'Last successful apt update was {age.days} days ago '
                        f'({last_update.strftime("%Y-%m-%d")}).'
                    ),
                    remediation='Run "apt update && apt upgrade" to apply pending updates.',
                    passed=False,
                ))
            else:
                findings.append(self._make_finding(
                    category='updates',
                    severity='info',
                    title='System updates are recent',
                    description=f'Last apt update was {age.days} days ago.',
                    remediation='No action needed.',
                    passed=True,
                ))
        except FileNotFoundError:
            # Stamp file may not exist on non-Debian or fresh installs
            pass
        except Exception as exc:
            self.logger.debug(f"Could not check update stamp: {exc}")

        return findings

    def _check_user_accounts(self) -> List[Dict[str, Any]]:
        """Check for dangerous user account configurations."""
        findings: List[Dict[str, Any]] = []

        # Parse /etc/passwd
        try:
            with open('/etc/passwd', 'r') as fh:
                passwd_lines = fh.readlines()
        except (FileNotFoundError, PermissionError) as exc:
            findings.append(self._make_finding(
                category='users',
                severity='medium',
                title='Cannot read /etc/passwd',
                description=f'Failed to read /etc/passwd: {exc}',
                remediation='Run the auditor with sufficient privileges.',
                passed=False,
            ))
            return findings

        # Valid no-login shells
        nologin_shells = {
            '/usr/sbin/nologin', '/sbin/nologin', '/bin/false',
            '/usr/bin/false',
        }

        # System accounts that are expected to have login shells
        login_expected = {'root'}

        uid_zero_users = []
        users_with_shells = []

        for line in passwd_lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) < 7:
                continue

            username = parts[0]
            uid = int(parts[2]) if parts[2].isdigit() else -1
            shell = parts[6]

            # UID 0 besides root
            if uid == 0 and username != 'root':
                uid_zero_users.append(username)

            # System users (UID < 1000, not root) with login shells
            if uid > 0 and uid < 1000 and username not in login_expected:
                if shell and shell not in nologin_shells and shell != '':
                    users_with_shells.append(f'{username} (shell: {shell})')

        if uid_zero_users:
            findings.append(self._make_finding(
                category='users',
                severity='critical',
                title='Non-root users have UID 0',
                description=(
                    f'The following users have UID 0 (root-equivalent): '
                    f'{", ".join(uid_zero_users)}. This is a serious security risk.'
                ),
                remediation=(
                    'Investigate these accounts immediately. Remove UID 0 from non-root '
                    'accounts or delete them if unauthorized.'
                ),
                passed=False,
            ))
        else:
            findings.append(self._make_finding(
                category='users',
                severity='info',
                title='No extra UID 0 accounts',
                description='Only root has UID 0.',
                remediation='No action needed.',
                passed=True,
            ))

        if users_with_shells:
            findings.append(self._make_finding(
                category='users',
                severity='medium',
                title='System accounts have login shells',
                description=(
                    f'The following system accounts have interactive login shells: '
                    f'{", ".join(users_with_shells)}.'
                ),
                remediation=(
                    'Set the shell to /usr/sbin/nologin for system accounts: '
                    '"usermod -s /usr/sbin/nologin <username>".'
                ),
                passed=False,
            ))
        else:
            findings.append(self._make_finding(
                category='users',
                severity='info',
                title='System accounts have no login shells',
                description='All system accounts use nologin or equivalent shells.',
                remediation='No action needed.',
                passed=True,
            ))

        # Check for users with empty passwords in /etc/shadow
        findings.extend(self._check_empty_passwords())

        return findings

    def _check_tls_certificates(self) -> List[Dict[str, Any]]:
        """Check TLS/SSL certificate expiry in common locations."""
        findings: List[Dict[str, Any]] = []

        cert_dirs = [
            '/etc/ssl/certs',
            '/etc/letsencrypt/live',
        ]

        cert_files_found = []

        for cert_dir in cert_dirs:
            if not os.path.isdir(cert_dir):
                continue

            if cert_dir == '/etc/letsencrypt/live':
                # Let's Encrypt stores certs in subdirectories
                try:
                    for domain_dir in os.listdir(cert_dir):
                        fullchain = os.path.join(cert_dir, domain_dir, 'fullchain.pem')
                        if os.path.isfile(fullchain):
                            cert_files_found.append(fullchain)
                except PermissionError:
                    findings.append(self._make_finding(
                        category='tls',
                        severity='medium',
                        title='Cannot read Let\'s Encrypt directory',
                        description=f'Permission denied accessing {cert_dir}.',
                        remediation='Run the auditor with sufficient privileges.',
                        passed=False,
                    ))
            else:
                # Check for .pem and .crt files (skip symlinks to avoid duplicates)
                try:
                    for name in os.listdir(cert_dir):
                        if name.endswith(('.pem', '.crt')):
                            fpath = os.path.join(cert_dir, name)
                            if os.path.isfile(fpath) and not os.path.islink(fpath):
                                cert_files_found.append(fpath)
                except PermissionError:
                    pass

        if not cert_files_found:
            findings.append(self._make_finding(
                category='tls',
                severity='info',
                title='No TLS certificates found to audit',
                description='No certificate files found in standard locations.',
                remediation='No action needed if TLS is not used on this server.',
                passed=True,
            ))
            return findings

        # Check expiry of each cert using openssl
        expiring_soon = []
        expired = []

        for cert_path in cert_files_found:
            expiry = self._get_cert_expiry(cert_path)
            if expiry is None:
                continue

            now = datetime.now(timezone.utc)
            remaining = expiry - now

            if remaining.total_seconds() < 0:
                expired.append((cert_path, expiry))
            elif remaining.days <= self.cert_expiry_warn_days:
                expiring_soon.append((cert_path, expiry, remaining.days))

        for cert_path, expiry in expired:
            findings.append(self._make_finding(
                category='tls',
                severity='critical',
                title='TLS certificate has expired',
                description=(
                    f'Certificate {cert_path} expired on '
                    f'{expiry.strftime("%Y-%m-%d %H:%M UTC")}.'
                ),
                remediation='Renew the certificate immediately. For Let\'s Encrypt: "certbot renew".',
                passed=False,
            ))

        for cert_path, expiry, days_left in expiring_soon:
            findings.append(self._make_finding(
                category='tls',
                severity='high',
                title='TLS certificate expiring soon',
                description=(
                    f'Certificate {cert_path} expires in {days_left} days '
                    f'(on {expiry.strftime("%Y-%m-%d %H:%M UTC")}).'
                ),
                remediation='Renew the certificate before it expires. For Let\'s Encrypt: "certbot renew".',
                passed=False,
            ))

        if not expired and not expiring_soon:
            findings.append(self._make_finding(
                category='tls',
                severity='info',
                title='TLS certificates are valid',
                description=(
                    f'Checked {len(cert_files_found)} certificate(s); '
                    f'all are valid for more than {self.cert_expiry_warn_days} days.'
                ),
                remediation='No action needed.',
                passed=True,
            ))

        return findings

    def _check_kernel_security(self) -> List[Dict[str, Any]]:
        """Check kernel security parameters (ASLR, IP forwarding)."""
        findings: List[Dict[str, Any]] = []

        # ASLR: kernel.randomize_va_space should be 2 (full randomization)
        aslr_value = self._read_sysctl('kernel.randomize_va_space')
        if aslr_value is not None:
            try:
                aslr_int = int(aslr_value)
            except ValueError:
                aslr_int = -1

            if aslr_int == 2:
                findings.append(self._make_finding(
                    category='kernel',
                    severity='info',
                    title='ASLR is fully enabled',
                    description='kernel.randomize_va_space = 2 (full randomization).',
                    remediation='No action needed.',
                    passed=True,
                ))
            elif aslr_int == 1:
                findings.append(self._make_finding(
                    category='kernel',
                    severity='medium',
                    title='ASLR is only partially enabled',
                    description=(
                        'kernel.randomize_va_space = 1 (partial). '
                        'Full randomization (2) is recommended.'
                    ),
                    remediation='Run "sysctl -w kernel.randomize_va_space=2" and persist in /etc/sysctl.conf.',
                    passed=False,
                ))
            else:
                findings.append(self._make_finding(
                    category='kernel',
                    severity='critical',
                    title='ASLR is disabled',
                    description=(
                        f'kernel.randomize_va_space = {aslr_int}. '
                        'Address Space Layout Randomization is off, making exploitation easier.'
                    ),
                    remediation='Run "sysctl -w kernel.randomize_va_space=2" and persist in /etc/sysctl.conf.',
                    passed=False,
                ))
        else:
            findings.append(self._make_finding(
                category='kernel',
                severity='medium',
                title='Cannot read ASLR setting',
                description='Failed to read kernel.randomize_va_space.',
                remediation='Ensure /proc/sys is accessible and check permissions.',
                passed=False,
            ))

        # IP forwarding: net.ipv4.ip_forward should be 0 for non-routers
        ip_forward = self._read_sysctl('net.ipv4.ip_forward')
        if ip_forward is not None:
            if ip_forward.strip() == '0':
                findings.append(self._make_finding(
                    category='kernel',
                    severity='info',
                    title='IP forwarding is disabled',
                    description='net.ipv4.ip_forward = 0.',
                    remediation='No action needed.',
                    passed=True,
                ))
            else:
                findings.append(self._make_finding(
                    category='kernel',
                    severity='medium',
                    title='IP forwarding is enabled',
                    description=(
                        f'net.ipv4.ip_forward = {ip_forward.strip()}. '
                        'Unless this server is a router or VPN gateway, forwarding should be off.'
                    ),
                    remediation=(
                        'If not needed, run "sysctl -w net.ipv4.ip_forward=0" '
                        'and persist in /etc/sysctl.conf.'
                    ),
                    passed=False,
                ))
        else:
            findings.append(self._make_finding(
                category='kernel',
                severity='medium',
                title='Cannot read IP forwarding setting',
                description='Failed to read net.ipv4.ip_forward.',
                remediation='Ensure /proc/sys is accessible.',
                passed=False,
            ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_finding(*, category: str, severity: str, title: str,
                      description: str, remediation: str,
                      passed: bool) -> Dict[str, Any]:
        """Construct a standardised finding dict."""
        return {
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'remediation': remediation,
            'passed': passed,
        }

    @staticmethod
    def _parse_sshd_config(content: str) -> Dict[str, str]:
        """
        Parse sshd_config content into a dict of directive -> value.
        Last occurrence wins (matching sshd behaviour for global scope).
        Keys are stored lower-cased for case-insensitive lookup.
        """
        directives: Dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Handle "Match" blocks -- stop at first Match to stay in global scope
            if line.lower().startswith('match '):
                break
            parts = line.split(None, 1)
            if len(parts) == 2:
                directives[parts[0].lower()] = parts[1]
        return directives

    @staticmethod
    def _parse_ss_output(output: str) -> List[Dict[str, Any]]:
        """Parse 'ss -tlnp' output into a list of port entries."""
        entries: List[Dict[str, Any]] = []
        for line in output.strip().splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 5:
                continue

            local_addr_port = parts[3]

            # Handle IPv6 bracket notation and plain addr:port
            if ']:' in local_addr_port:
                # [::]:port or [::1]:port
                bracket_end = local_addr_port.rindex(']:')
                addr = local_addr_port[1:bracket_end]
                port_str = local_addr_port[bracket_end + 2:]
            elif local_addr_port.startswith('['):
                # edge case, just port
                addr = local_addr_port
                port_str = '0'
            else:
                # addr:port or *:port
                last_colon = local_addr_port.rfind(':')
                if last_colon == -1:
                    continue
                addr = local_addr_port[:last_colon]
                port_str = local_addr_port[last_colon + 1:]

            try:
                port = int(port_str)
            except ValueError:
                continue

            # Extract process name if available
            process = ''
            if len(parts) >= 6:
                proc_match = re.search(r'"([^"]+)"', parts[-1])
                if proc_match:
                    process = proc_match.group(1)

            entries.append({
                'address': addr,
                'port': port,
                'process': process,
            })

        return entries

    def _check_file_mode(self, path: str, expected_modes: set,
                         category: str, description_label: str,
                         expected_str: str) -> List[Dict[str, Any]]:
        """Check that a file/directory has one of the expected permission modes."""
        findings: List[Dict[str, Any]] = []
        try:
            st = os.stat(path)
            actual_mode = st.st_mode & 0o7777
            if actual_mode not in expected_modes:
                findings.append(self._make_finding(
                    category=category,
                    severity='high',
                    title=f'Incorrect permissions on {path}',
                    description=(
                        f'{path} ({description_label}) has permissions '
                        f'{oct(actual_mode)} but should be {expected_str}.'
                    ),
                    remediation=f'Run "chmod {expected_str.split()[0]} {path}".',
                    passed=False,
                ))
            else:
                findings.append(self._make_finding(
                    category=category,
                    severity='info',
                    title=f'Permissions OK on {path}',
                    description=f'{path} has correct permissions ({oct(actual_mode)}).',
                    remediation='No action needed.',
                    passed=True,
                ))
        except FileNotFoundError:
            findings.append(self._make_finding(
                category=category,
                severity='info',
                title=f'{path} not found',
                description=f'{path} does not exist on this system.',
                remediation='No action needed if the service is not installed.',
                passed=True,
            ))
        except PermissionError:
            findings.append(self._make_finding(
                category=category,
                severity='medium',
                title=f'Cannot stat {path}',
                description=f'Permission denied accessing {path}.',
                remediation='Run the auditor with sufficient privileges.',
                passed=False,
            ))
        return findings

    def _check_home_directories(self) -> List[Dict[str, Any]]:
        """Check that home directories are not world-readable."""
        findings: List[Dict[str, Any]] = []
        world_readable = []

        home_base = '/home'
        try:
            if not os.path.isdir(home_base):
                return findings

            for username in os.listdir(home_base):
                home_path = os.path.join(home_base, username)
                if not os.path.isdir(home_path):
                    continue
                try:
                    mode = os.stat(home_path).st_mode & 0o7777
                    # World-readable if others have read (o+r = 0o004)
                    if mode & 0o004:
                        world_readable.append(f'{home_path} ({oct(mode)})')
                except (PermissionError, OSError):
                    continue
        except PermissionError:
            pass

        if world_readable:
            findings.append(self._make_finding(
                category='permissions',
                severity='medium',
                title='Home directories are world-readable',
                description=(
                    f'The following home directories are world-readable: '
                    f'{", ".join(world_readable)}.'
                ),
                remediation='Run "chmod 750 /home/<user>" for each affected directory.',
                passed=False,
            ))
        else:
            findings.append(self._make_finding(
                category='permissions',
                severity='info',
                title='Home directories are not world-readable',
                description='No home directories are world-readable.',
                remediation='No action needed.',
                passed=True,
            ))

        return findings

    def _check_world_writable_etc(self) -> List[Dict[str, Any]]:
        """Check for world-writable files in /etc."""
        findings: List[Dict[str, Any]] = []

        try:
            result = subprocess.run(
                ['find', '/etc', '-maxdepth', '2', '-type', 'f', '-perm', '-0002'],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                writable_files = [
                    f for f in result.stdout.strip().splitlines() if f
                ]
                if writable_files:
                    display = writable_files[:20]  # cap display at 20
                    findings.append(self._make_finding(
                        category='permissions',
                        severity='high',
                        title='World-writable files found in /etc',
                        description=(
                            f'Found {len(writable_files)} world-writable file(s) in /etc: '
                            f'{", ".join(display)}'
                            f'{"..." if len(writable_files) > 20 else ""}.'
                        ),
                        remediation='Remove world-writable permission: "chmod o-w <file>" for each file.',
                        passed=False,
                    ))
                else:
                    findings.append(self._make_finding(
                        category='permissions',
                        severity='info',
                        title='No world-writable files in /etc',
                        description='No world-writable files were found in /etc.',
                        remediation='No action needed.',
                        passed=True,
                    ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            findings.append(self._make_finding(
                category='permissions',
                severity='info',
                title='Could not check world-writable files',
                description='The find command was unavailable or timed out.',
                remediation='Manually check: find /etc -type f -perm -0002',
                passed=False,
            ))

        return findings

    def _check_empty_passwords(self) -> List[Dict[str, Any]]:
        """Check /etc/shadow for users with empty password fields."""
        findings: List[Dict[str, Any]] = []

        try:
            with open('/etc/shadow', 'r') as fh:
                shadow_lines = fh.readlines()
        except (FileNotFoundError, PermissionError):
            # Cannot read shadow -- not necessarily an error, just insufficient perms
            findings.append(self._make_finding(
                category='users',
                severity='medium',
                title='Cannot read /etc/shadow',
                description='Permission denied reading /etc/shadow; empty password check skipped.',
                remediation='Run the auditor as root to enable this check.',
                passed=False,
            ))
            return findings

        empty_pw_users = []
        for line in shadow_lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) < 2:
                continue
            username = parts[0]
            password_hash = parts[1]
            # Empty string or "!" or "*" or "!!" mean locked/no-password
            # An actual empty field means empty password
            if password_hash == '':
                empty_pw_users.append(username)

        if empty_pw_users:
            findings.append(self._make_finding(
                category='users',
                severity='critical',
                title='Users with empty passwords',
                description=(
                    f'The following users have empty passwords: '
                    f'{", ".join(empty_pw_users)}.'
                ),
                remediation=(
                    'Lock or set passwords for these accounts: '
                    '"passwd -l <username>" to lock, or "passwd <username>" to set a password.'
                ),
                passed=False,
            ))
        else:
            findings.append(self._make_finding(
                category='users',
                severity='info',
                title='No users with empty passwords',
                description='No empty password fields found in /etc/shadow.',
                remediation='No action needed.',
                passed=True,
            ))

        return findings

    def _get_cert_expiry(self, cert_path: str) -> Optional[datetime]:
        """Use openssl to get the expiry date of a certificate file."""
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-enddate', '-noout', '-in', cert_path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return None

            # Output is like: notAfter=Jan 15 12:00:00 2025 GMT
            match = re.search(r'notAfter=(.+)', result.stdout)
            if not match:
                return None

            date_str = match.group(1).strip()
            # Parse the date -- openssl uses a consistent format
            try:
                expiry = datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
                return expiry.replace(tzinfo=timezone.utc)
            except ValueError:
                # Try alternate format
                try:
                    expiry = datetime.strptime(date_str, '%b  %d %H:%M:%S %Y %Z')
                    return expiry.replace(tzinfo=timezone.utc)
                except ValueError:
                    self.logger.debug(f"Could not parse cert date: {date_str}")
                    return None

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    @staticmethod
    def _read_sysctl(key: str) -> Optional[str]:
        """Read a sysctl value from /proc/sys or via the sysctl command."""
        # Try /proc/sys first (fastest, no subprocess)
        proc_path = '/proc/sys/' + key.replace('.', '/')
        try:
            with open(proc_path, 'r') as fh:
                return fh.read().strip()
        except (FileNotFoundError, PermissionError):
            pass

        # Fall back to sysctl command
        try:
            result = subprocess.run(
                ['sysctl', '-n', key],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return None

    # ------------------------------------------------------------------
    # Results handling
    # ------------------------------------------------------------------

    def _publish_results(self, findings: List[Dict[str, Any]]):
        """Publish audit results to the event bus."""
        total = len(findings)
        passed = sum(1 for f in findings if f['passed'])
        failed = total - passed

        severity_counts: Dict[str, int] = {}
        for f in findings:
            if not f['passed']:
                sev = f['severity']
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary = {
            'total_checks': total,
            'passed': passed,
            'failed': failed,
            'severity_counts': severity_counts,
            'findings': findings,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }

        self.event_bus.publish(
            event_type='hardening_audit_complete',
            data=summary,
            priority=EventPriority.HIGH if severity_counts.get('critical', 0) > 0 else EventPriority.NORMAL,
            source='HardeningAuditor',
        )

    def _store_results(self, findings: List[Dict[str, Any]]):
        """Store audit results in the database audit_log table."""
        try:
            self.db.add_audit_log(
                event_type='hardening_audit',
                actor='HardeningAuditor',
                target='system',
                details={
                    'total_checks': len(findings),
                    'passed': sum(1 for f in findings if f['passed']),
                    'failed': sum(1 for f in findings if not f['passed']),
                    'findings': findings,
                },
            )
        except Exception as exc:
            self.logger.error(f"Failed to store audit results: {exc}", exc_info=True)

    def _log_findings(self, findings: List[Dict[str, Any]]):
        """Log findings at appropriate severity levels."""
        severity_to_log = {
            'critical': self.logger.error,
            'high': self.logger.warning,
            'medium': self.logger.warning,
            'low': self.logger.info,
            'info': self.logger.debug,
        }

        failed_findings = [f for f in findings if not f['passed']]
        passed_count = len(findings) - len(failed_findings)

        if not failed_findings:
            self.logger.info("Hardening audit: all checks passed")
            return

        self.logger.info(
            f"Hardening audit: {passed_count} passed, "
            f"{len(failed_findings)} failed"
        )

        for finding in failed_findings:
            log_fn = severity_to_log.get(finding['severity'], self.logger.info)
            log_fn(
                f"[{finding['severity'].upper()}] {finding['category']}: "
                f"{finding['title']} -- {finding['description']}"
            )
