#!/usr/bin/env python3
"""
Security utilities for SSH MCP Server
Provides input validation and command sanitization
"""

import re
import ipaddress
import shlex
from typing import Optional, List, Tuple


def validate_hostname(hostname: str) -> bool:
    """Validate hostname format according to RFC 1123"""
    if not hostname or len(hostname) > 255:
        return False
    
    # Remove trailing dot if present
    if hostname.endswith("."):
        hostname = hostname[:-1]
    
    # Check each label
    labels = hostname.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', label):
            return False
    
    return True


def validate_ip_address(ip: str) -> bool:
    """Validate IP address (IPv4 or IPv6)"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_destination(destination: str) -> Tuple[bool, str]:
    """
    Validate a destination (hostname or IP address)
    Returns: (is_valid, error_message)
    """
    if not destination:
        return False, "Destination cannot be empty"
    
    # Check if it's an IP address
    if validate_ip_address(destination):
        return True, ""
    
    # Check if it's a valid hostname
    if validate_hostname(destination):
        return True, ""
    
    return False, f"Invalid destination format: {destination}"


def sanitize_command_argument(arg: str, allowed_chars: Optional[str] = None) -> str:
    """
    Sanitize command line arguments to prevent injection
    Default allows alphanumeric, dots, hyphens, underscores, colons (for IPv6)
    """
    if allowed_chars is None:
        # Safe default character set
        allowed_chars = r'[^a-zA-Z0-9._\-:/]'
    
    # Remove any characters not in the allowed set
    sanitized = re.sub(allowed_chars, '', arg)
    
    # Additional safety: remove any shell metacharacters
    dangerous_chars = ['&', '|', ';', '$', '`', '\\', '(', ')', '<', '>', '"', "'", '\n', '\r']
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized


def validate_interface_name(interface: str) -> bool:
    """Validate network interface name or IP address for source interface"""
    if not interface:
        return False
    
    # Check if it's an IP address (for -I parameter)
    if validate_ip_address(interface):
        return True
    
    # Common interface patterns
    patterns = [
        r'^eth\d+$',          # eth0, eth1, etc.
        r'^en[ospx]\d+$',     # macOS: en0, enp0s3, etc.
        r'^wlan\d+$',         # wlan0, wlan1
        r'^lo$',              # loopback
        r'^docker\d+$',       # docker interfaces
        r'^br-[a-f0-9]+$',    # bridge interfaces
        r'^[a-zA-Z0-9_\-]+$'  # Generic pattern
    ]
    
    return any(re.match(pattern, interface) for pattern in patterns)


def validate_file_path(path: str, allow_relative: bool = False) -> Tuple[bool, str]:
    """
    Validate file path for safety
    Returns: (is_valid, error_message)
    """
    if not path:
        return False, "Path cannot be empty"
    
    # Check for directory traversal attempts
    if '..' in path:
        return False, "Path cannot contain '..' (directory traversal)"
    
    # Check for null bytes
    if '\x00' in path:
        return False, "Path cannot contain null bytes"
    
    # Check for absolute path requirement
    if not allow_relative and not path.startswith('/'):
        return False, "Path must be absolute (start with /)"
    
    # Sanitize path
    safe_path = sanitize_command_argument(path, allowed_chars=r'[^a-zA-Z0-9._\-/~]')
    if safe_path != path:
        return False, f"Path contains invalid characters"
    
    return True, ""


def is_safe_command(command: str) -> Tuple[bool, str]:
    """
    Check if a command is safe to execute
    Returns: (is_safe, reason)
    """
    # Check for command chaining
    dangerous_patterns = [
        ('&&', 'Command chaining with && is not allowed'),
        ('||', 'Command chaining with || is not allowed'),
        (';', 'Command separation with ; is not allowed'),
        ('|', 'Piping with | is not allowed'),
        ('`', 'Command substitution with backticks is not allowed'),
        ('$(', 'Command substitution with $() is not allowed'),
        ('>', 'Output redirection is not allowed'),
        ('<', 'Input redirection is not allowed'),
        ('&', 'Background execution is not allowed'),
    ]
    
    for pattern, reason in dangerous_patterns:
        if pattern in command:
            return False, reason
    
    # Check for environment variable expansion
    if '$' in command and not command.startswith('echo $'):
        return False, "Environment variable expansion is not allowed"
    
    return True, ""


def build_safe_command(base_cmd: str, args: List[str], validate_args: bool = True) -> str:
    """
    Build a safe command string from base command and arguments
    Uses shlex to properly quote arguments
    """
    if validate_args:
        safe_args = [sanitize_command_argument(arg) for arg in args]
    else:
        safe_args = args
    
    # Use shlex to properly quote arguments
    quoted_args = [shlex.quote(arg) for arg in safe_args]
    
    return f"{base_cmd} {' '.join(quoted_args)}"


def validate_mtu_size(mtu: int) -> Tuple[bool, str]:
    """
    Validate MTU size is within reasonable bounds
    """
    if not isinstance(mtu, int):
        return False, "MTU must be an integer"
    
    if mtu < 68:  # Minimum IPv4 MTU
        return False, "MTU must be at least 68 bytes"
    
    if mtu > 65535:  # Maximum possible
        return False, "MTU cannot exceed 65535 bytes"
    
    return True, ""


def validate_port_number(port: int) -> bool:
    """Validate TCP/UDP port number"""
    return isinstance(port, int) and 1 <= port <= 65535


def get_safe_command_whitelist() -> List[str]:
    """
    Get list of whitelisted commands that are safe to execute
    """
    return [
        'ls', 'pwd', 'whoami', 'hostname', 'date', 'uptime',
        'df', 'du', 'free', 'ps', 'top', 'htop',
        'cat', 'head', 'tail', 'grep', 'awk', 'sed',
        'ping', 'traceroute', 'tracepath', 'nslookup', 'dig',
        'netstat', 'ss', 'ip', 'ifconfig', 'route',
        'systemctl', 'service', 'journalctl',
        'docker', 'kubectl', 'git',
        'python', 'python3', 'node', 'npm',
        'echo', 'which', 'wc', 'sort', 'uniq'
    ]