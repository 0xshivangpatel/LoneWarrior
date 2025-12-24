"""
Input validation utilities for security

This module provides strict input validation to prevent:
- Command injection attacks
- Privilege escalation via crafted inputs
- Path traversal attacks
- Other injection vulnerabilities

All validation functions are designed to be strict and fail-safe.
"""

import ipaddress
import os
import re
from typing import Optional, List


# Characters that are NEVER allowed in any input
DANGEROUS_CHARS = set(';&|`$(){}[]<>\\!*?\n\r\t\x00')

# Maximum lengths for various inputs
MAX_IP_LENGTH = 45  # IPv6 max
MAX_USERNAME_LENGTH = 32
MAX_PATH_LENGTH = 4096
MAX_CHAIN_NAME_LENGTH = 32


def _contains_dangerous_chars(s: str) -> bool:
    """Check if string contains dangerous shell characters"""
    return bool(set(s) & DANGEROUS_CHARS)


def validate_ip_address(ip_str: str) -> bool:
    """
    Validate IP address format to prevent command injection

    Args:
        ip_str: IP address string to validate

    Returns:
        True if valid IPv4 or IPv6 address, False otherwise
    """
    if not ip_str or not isinstance(ip_str, str):
        return False

    # Length check
    if len(ip_str) > MAX_IP_LENGTH:
        return False

    # Remove whitespace
    ip_str = ip_str.strip()

    # Check for dangerous characters first
    if _contains_dangerous_chars(ip_str):
        return False

    # Basic format check (prevents obvious injection attempts)
    # Only allow: digits, dots, colons, hex chars, and brackets for IPv6
    if not re.match(r'^[0-9a-fA-F:.\[\]/]+$', ip_str):
        return False

    # Handle CIDR notation
    if '/' in ip_str:
        parts = ip_str.split('/', 1)
        if len(parts) != 2:
            return False
        ip_part, prefix = parts
        try:
            if not prefix.isdigit():
                return False
            prefix_int = int(prefix)
            # Check valid prefix range
            addr = ipaddress.ip_address(ip_part)
            max_prefix = 32 if addr.version == 4 else 128
            if not (0 <= prefix_int <= max_prefix):
                return False
            return True
        except ValueError:
            return False

    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_ip_address_or_raise(ip_str: str) -> str:
    """
    Validate IP address and raise ValueError if invalid

    Args:
        ip_str: IP address string to validate

    Returns:
        Validated and normalized IP address string

    Raises:
        ValueError: If IP address is invalid
    """
    if not validate_ip_address(ip_str):
        raise ValueError(f"Invalid IP address format: {repr(ip_str)[:50]}")
    return ip_str.strip()


def validate_username(username: str) -> bool:
    """
    Validate Linux username format

    Args:
        username: Username to validate

    Returns:
        True if valid username format
    """
    if not username or not isinstance(username, str):
        return False

    if len(username) > MAX_USERNAME_LENGTH:
        return False

    # Check for dangerous characters
    if _contains_dangerous_chars(username):
        return False

    # Standard Linux username format
    # Must start with lowercase letter or underscore
    # Can contain lowercase letters, digits, underscores, hyphens
    return bool(re.match(r'^[a-z_][a-z0-9_-]*$', username))


def validate_username_or_raise(username: str) -> str:
    """
    Validate username and raise ValueError if invalid

    Args:
        username: Username to validate

    Returns:
        Validated username

    Raises:
        ValueError: If username is invalid
    """
    if not validate_username(username):
        raise ValueError(f"Invalid username format: {repr(username)[:50]}")
    return username


def validate_pid(pid: int) -> bool:
    """
    Validate process ID

    Args:
        pid: Process ID to validate

    Returns:
        True if valid PID
    """
    if not isinstance(pid, int):
        return False

    # PIDs must be positive and reasonable
    if pid < 1 or pid > 4194304:  # Linux max PID
        return False

    # Protect critical PIDs
    if pid == 1:  # init/systemd
        return False

    # Don't allow killing ourselves
    if pid == os.getpid():
        return False

    return True


def validate_pid_or_raise(pid: int) -> int:
    """
    Validate PID and raise ValueError if invalid

    Args:
        pid: Process ID to validate

    Returns:
        Validated PID

    Raises:
        ValueError: If PID is invalid
    """
    if not validate_pid(pid):
        raise ValueError(f"Invalid or protected PID: {pid}")
    return pid


def validate_chain_name(chain: str, allowed_chains: Optional[List[str]] = None) -> bool:
    """
    Validate iptables chain name

    Args:
        chain: Chain name to validate
        allowed_chains: Optional list of allowed chain names

    Returns:
        True if valid chain name
    """
    if not chain or not isinstance(chain, str):
        return False

    if len(chain) > MAX_CHAIN_NAME_LENGTH:
        return False

    # Check for dangerous characters
    if _contains_dangerous_chars(chain):
        return False

    # Chain names should be alphanumeric with underscores
    if not re.match(r'^[A-Z][A-Z0-9_]*$', chain):
        return False

    # If allowed list provided, check membership
    if allowed_chains is not None:
        return chain in allowed_chains

    return True


def validate_port(port: int) -> bool:
    """
    Validate network port number

    Args:
        port: Port number to validate

    Returns:
        True if valid port
    """
    if not isinstance(port, int):
        return False

    return 1 <= port <= 65535


def validate_port_or_raise(port: int) -> int:
    """
    Validate port and raise ValueError if invalid

    Args:
        port: Port number to validate

    Returns:
        Validated port

    Raises:
        ValueError: If port is invalid
    """
    if not validate_port(port):
        raise ValueError(f"Invalid port number: {port}")
    return port


def sanitize_for_logging(s: str, max_length: int = 200) -> str:
    """
    Sanitize a string for safe logging (no injection via logs)

    Args:
        s: String to sanitize
        max_length: Maximum length to keep

    Returns:
        Sanitized string safe for logging
    """
    if not s:
        return ""

    # Remove null bytes and control characters
    sanitized = ''.join(c if c.isprintable() or c == ' ' else '?' for c in s)

    # Truncate
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + '...'

    return sanitized

