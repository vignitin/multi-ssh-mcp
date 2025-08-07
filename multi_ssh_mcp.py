#!/usr/bin/env python3
"""
Multi-Server SSH MCP Server using FastMCP

A modern Model Context Protocol server that can connect to multiple SSH servers
defined in a JSON configuration file using FastMCP framework.

Usage:
    uv run ssh_server.py [config_file_path]
    python ssh_server.py [config_file_path]
"""

import json
import os
import sys
import argparse
from pathlib import Path
from typing import Any, Dict, Optional, List
import logging

import paramiko
from fastmcp import FastMCP
import jc

# Import security utilities
from security_utils import (
    validate_destination,
    validate_file_path,
    validate_interface_name,
    is_safe_command,
    sanitize_command_argument,
    build_safe_command
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ssh-mcp-server")

class SSHServerManager:
    """Manages SSH connections to multiple servers defined in config"""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.servers_config = {}
        self.current_connection = None
        self.current_server = None
        self.auto_parse_commands = []
        self.load_config()
    
    def load_config(self):
        """Load server configurations from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                self.servers_config = config.get('ssh_servers', {})
                # Load auto-parse configuration if present
                self.auto_parse_commands = config.get('auto_parse_commands', [
                    'ls', 'ps', 'df', 'netstat', 'ss', 'ifconfig', 'ip', 
                    'uptime', 'w', 'who', 'mount', 'systemctl', 'service',
                    'arp', 'route', 'dig', 'ping', 'traceroute', 'iostat',
                    'vmstat', 'free', 'lsof', 'lsblk', 'lsusb', 'lspci'
                ])
                logger.info(f"Loaded {len(self.servers_config)} server configurations")
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {self.config_path}")
            self.servers_config = {}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            self.servers_config = {}
    
    def get_server_list(self) -> List[Dict[str, Any]]:
        """Get list of available servers"""
        servers = []
        for name, config in self.servers_config.items():
            servers.append({
                'name': name,
                'host': config.get('host', ''),
                'port': config.get('port', 22),
                'username': config.get('username', ''),
                'description': config.get('description', ''),
                'auth_method': config.get('auth_method', 'password')
            })
        return servers
    
    def disconnect(self):
        """Disconnect from current server"""
        if self.current_connection:
            try:
                self.current_connection.close()
                logger.info(f"Disconnected from {self.current_server}")
            except Exception as e:
                logger.error(f"Error disconnecting: {e}")
            finally:
                self.current_connection = None
                self.current_server = None
    
    def connect(self, server_name: str) -> Dict[str, Any]:
        """Connect to a specific server"""
        if server_name not in self.servers_config:
            return {
                'success': False, 
                'error': f"Server '{server_name}' not found in configuration"
            }
        
        # Disconnect from current server if connected to a different one
        if self.current_connection and self.current_server != server_name:
            self.disconnect()
        
        # If already connected to this server, return success
        if self.current_connection and self.current_server == server_name:
            return {
                'success': True,
                'message': f"Already connected to {server_name}"
            }
        
        config = self.servers_config[server_name]
        
        try:
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Prepare connection parameters
            host = config['host']
            port = config.get('port', 22)
            username = config['username']
            
            connect_kwargs = {
                'hostname': host,
                'port': port,
                'username': username,
                'timeout': config.get('timeout', 30)
            }
            
            # Handle authentication
            auth_method = config.get('auth_method', 'password')
            
            if auth_method == 'password':
                password = config.get('password')
                if password and password.startswith('${ENV:'):
                    # Extract environment variable name
                    env_var = password[6:-1]  # Remove ${ENV: and }
                    password = os.getenv(env_var)
                    if not password:
                        return {
                            'success': False,
                            'error': f"Environment variable {env_var} not set"
                        }
                connect_kwargs['password'] = password
                
            elif auth_method == 'key':
                key_path = config.get('private_key_path')
                if not key_path:
                    return {
                        'success': False,
                        'error': "private_key_path required for key authentication"
                    }
                
                # Expand user path
                key_path = os.path.expanduser(key_path)
                if not os.path.exists(key_path):
                    return {
                        'success': False,
                        'error': f"Private key file not found: {key_path}"
                    }
                
                connect_kwargs['key_filename'] = key_path
                
                # Handle key passphrase if provided
                passphrase = config.get('key_passphrase')
                if passphrase and passphrase.startswith('${ENV:'):
                    env_var = passphrase[6:-1]
                    passphrase = os.getenv(env_var)
                if passphrase:
                    connect_kwargs['passphrase'] = passphrase
            
            # Connect
            client.connect(**connect_kwargs)
            
            self.current_connection = client
            self.current_server = server_name
            
            return {
                'success': True,
                'message': f"Successfully connected to {server_name} ({host}:{port})"
            }
            
        except paramiko.AuthenticationException:
            return {
                'success': False,
                'error': f"Authentication failed for {server_name}"
            }
        except paramiko.SSHException as e:
            return {
                'success': False,
                'error': f"SSH connection failed: {str(e)}"
            }
        except Exception as e:
            return {
                'success': False,
                'error': f"Connection error: {str(e)}"
            }
    
    def execute_command(self, command: str, server_name: str = None, parse_output: bool = None) -> Dict[str, Any]:
        """Execute command on current or specified server with optional output parsing
        
        Args:
            command: Command to execute
            server_name: Optional server to connect to
            parse_output: Whether to parse output (None=auto-detect, True=force, False=disable)
        """
        # Security check: validate command safety
        is_safe, reason = is_safe_command(command)
        if not is_safe:
            return {
                'success': False,
                'error': f"Command rejected for security reasons: {reason}"
            }
        
        # Connect to server if specified and not already connected
        if server_name and server_name != self.current_server:
            connect_result = self.connect(server_name)
            if not connect_result['success']:
                return connect_result
        
        if not self.current_connection:
            return {
                'success': False,
                'error': "Not connected to any server. Use connect_server first."
            }
        
        try:
            stdin, stdout, stderr = self.current_connection.exec_command(command)
            
            # Read output
            stdout_data = stdout.read().decode('utf-8')
            stderr_data = stderr.read().decode('utf-8')
            exit_code = stdout.channel.recv_exit_status()
            
            result = {
                'success': True,
                'server': self.current_server,
                'command': command,
                'exit_code': exit_code,
                'stdout': stdout_data,
                'stderr': stderr_data
            }
            
            # Determine if we should parse output
            base_command = command.split()[0].split('/')[-1]
            should_parse = parse_output
            
            # Auto-detect if parse_output is None
            if parse_output is None:
                should_parse = base_command in self.auto_parse_commands
            
            # Try to parse output with jc if needed
            if should_parse and stdout_data:
                try:
                    # Extract base command (first word, without path)
                    base_command = command.split()[0].split('/')[-1]
                    
                    # Check if jc has a parser for this command
                    if base_command in jc.parser_mod_list():
                        parsed_data = jc.parse(base_command, stdout_data)
                        result['parsed_output'] = parsed_data
                        result['parser_used'] = base_command
                    else:
                        result['parse_note'] = f"No jc parser available for command: {base_command}"
                except Exception as e:
                    # If parsing fails, just note it but don't fail the whole command
                    result['parse_error'] = f"Failed to parse output: {str(e)}"
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Command execution failed: {str(e)}"
            }
    
    def upload_file(self, local_path: str, remote_path: str, server_name: str = None) -> Dict[str, Any]:
        """Upload file to current or specified server"""
        # Validate remote path
        is_valid, error_msg = validate_file_path(remote_path, allow_relative=False)
        if not is_valid:
            return {
                'success': False,
                'error': f"Invalid remote path: {error_msg}"
            }
        
        # Connect to server if specified and not already connected
        if server_name and server_name != self.current_server:
            connect_result = self.connect(server_name)
            if not connect_result['success']:
                return connect_result
        
        if not self.current_connection:
            return {
                'success': False,
                'error': "Not connected to any server. Use connect_server first."
            }
        
        # Resolve local path to absolute and check existence
        local_path = os.path.abspath(local_path)
        if not os.path.exists(local_path):
            return {
                'success': False,
                'error': f"Local file not found: {local_path}"
            }
        
        try:
            sftp = self.current_connection.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            
            return {
                'success': True,
                'server': self.current_server,
                'message': f"Successfully uploaded {local_path} to {remote_path}"
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"File upload failed: {str(e)}"
            }
    
    def download_file(self, remote_path: str, local_path: str, server_name: str = None) -> Dict[str, Any]:
        """Download file from current or specified server"""
        # Validate remote path
        is_valid, error_msg = validate_file_path(remote_path, allow_relative=False)
        if not is_valid:
            return {
                'success': False,
                'error': f"Invalid remote path: {error_msg}"
            }
        
        # Connect to server if specified and not already connected
        if server_name and server_name != self.current_server:
            connect_result = self.connect(server_name)
            if not connect_result['success']:
                return connect_result
        
        if not self.current_connection:
            return {
                'success': False,
                'error': "Not connected to any server. Use connect_server first."
            }
        
        try:
            sftp = self.current_connection.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            
            return {
                'success': True,
                'server': self.current_server,
                'message': f"Successfully downloaded {remote_path} to {local_path}"
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"File download failed: {str(e)}"
            }


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Multi-Server SSH MCP Server using FastMCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    uv run ssh_server.py                          # Uses ssh_servers.json
    uv run ssh_server.py /path/to/config.json     # Uses specified config
    python ssh_server.py --config servers.json    # Uses servers.json
        """
    )
    
    parser.add_argument(
        'config_file',
        nargs='?',
        default='servers.json',
        help='Path to SSH servers configuration file (default: servers.json)'
    )
    
    parser.add_argument(
        '--config', '-c',
        dest='config_file_alt',
        help='Alternative way to specify config file path'
    )
    
    return parser.parse_args()


def main():
    # Parse command line arguments
    args = parse_arguments()
    
    # Determine config file path (--config flag takes precedence)
    config_file = args.config_file_alt if args.config_file_alt else args.config_file
    
    # Convert to absolute path and verify existence
    config_path = os.path.abspath(config_file)
    
    if not os.path.exists(config_path):
        print(f"Error: Configuration file not found: {config_path}", file=sys.stderr)
        print(f"Please create the configuration file or specify a valid path.", file=sys.stderr)
        print(f"Example: uv run {sys.argv[0]} /path/to/your/config.json", file=sys.stderr)
        sys.exit(1)
    
    # Initialize SSH manager with the specified config file
    ssh_manager = SSHServerManager(config_path)
    
    # Check if any servers were loaded
    if not ssh_manager.servers_config:
        print(f"Error: No servers found in configuration file: {config_path}", file=sys.stderr)
        print(f"Please check the configuration file format.", file=sys.stderr)
        sys.exit(1)
    
    logger.info(f"Starting FastMCP SSH Server with config: {config_path}")
    logger.info(f"Loaded {len(ssh_manager.servers_config)} server(s): {', '.join(ssh_manager.servers_config.keys())}")
    
    # Create FastMCP server
    mcp = FastMCP("Multi-SSH Server")
    
    @mcp.tool()
    def list_servers() -> str:
        """List all configured SSH servers with their details"""
        servers = ssh_manager.get_server_list()
        if not servers:
            return "No servers configured. Check your configuration file."
        
        result = "Available SSH Servers:\n\n"
        for server in servers:
            result += f"• {server['name']}\n"
            result += f"  Host: {server['host']}:{server['port']}\n"
            result += f"  User: {server['username']}\n"
            result += f"  Auth: {server['auth_method']}\n"
            if server['description']:
                result += f"  Description: {server['description']}\n"
            result += "\n"
        
        return result
    
    @mcp.tool()
    def connect_server(server_name: str) -> str:
        """Connect to a specific SSH server
        
        Args:
            server_name: Name of the server to connect to
        """
        result = ssh_manager.connect(server_name)
        
        if result['success']:
            return result['message']
        else:
            return f"Connection failed: {result['error']}"
    
    @mcp.tool()
    def disconnect_server() -> str:
        """Disconnect from the current SSH server"""
        if ssh_manager.current_connection:
            server_name = ssh_manager.current_server
            ssh_manager.disconnect()
            return f"Disconnected from {server_name}"
        else:
            return "No active connection to disconnect"
    
    @mcp.tool()
    def execute_command(command: str, server_name: str = None, parse_output: bool = None) -> str:
        """Execute a command on the current or specified SSH server
        
        Args:
            command: Command to execute
            server_name: Optional server to connect to and execute command on
            parse_output: Whether to parse output (None=auto-detect, True=force, False=disable)
        """
        result = ssh_manager.execute_command(command, server_name, parse_output)
        
        if result['success']:
            output = f"Command executed on {result['server']}: {result['command']}\n"
            output += f"Exit code: {result['exit_code']}\n\n"
            
            if result['stdout']:
                output += f"STDOUT:\n{result['stdout']}\n"
            
            if result['stderr']:
                output += f"STDERR:\n{result['stderr']}\n"
            
            if 'parsed_output' in result:
                output += f"\nPARSED OUTPUT:\n{json.dumps(result['parsed_output'], indent=2)}\n"
                output += f"Parser used: {result['parser_used']}\n"
            elif 'parse_note' in result:
                output += f"\nPARSING NOTE: {result['parse_note']}\n"
            elif 'parse_error' in result:
                output += f"\nPARSING ERROR: {result['parse_error']}\n"
            
            return output
        else:
            return f"Command failed: {result['error']}"
    
    @mcp.tool()
    def upload_file(local_path: str, remote_path: str, server_name: str = None) -> str:
        """Upload a file to the current or specified SSH server
        
        Args:
            local_path: Local file path
            remote_path: Remote file path
            server_name: Optional server to upload to
        """
        result = ssh_manager.upload_file(local_path, remote_path, server_name)
        
        if result['success']:
            return result['message']
        else:
            return f"Upload failed: {result['error']}"
    
    @mcp.tool()
    def download_file(remote_path: str, local_path: str, server_name: str = None) -> str:
        """Download a file from the current or specified SSH server
        
        Args:
            remote_path: Remote file path
            local_path: Local file path
            server_name: Optional server to download from
        """
        result = ssh_manager.download_file(remote_path, local_path, server_name)
        
        if result['success']:
            return result['message']
        else:
            return f"Download failed: {result['error']}"
    
    @mcp.tool()
    def get_current_connection() -> str:
        """Get information about the current SSH connection"""
        if ssh_manager.current_connection and ssh_manager.current_server:
            config = ssh_manager.servers_config[ssh_manager.current_server]
            return f"Currently connected to: {ssh_manager.current_server} ({config['host']}:{config.get('port', 22)})"
        else:
            return "No active SSH connection"
    
    @mcp.tool()
    def ping(destination: str, server_name: str = None, count: int = 5, source_interface: str = None) -> str:
        """Execute ping command with security validation
        
        Args:
            destination: Target host or IP to ping
            server_name: Optional server to run ping from
            count: Number of ping packets (default: 5, max: 10)
            source_interface: Optional source interface or IP
        """
        # Validate destination
        is_valid, error_msg = validate_destination(destination)
        if not is_valid:
            return f"Invalid destination: {error_msg}"
        
        # Validate count
        if not isinstance(count, int) or count < 1 or count > 10:
            return "Count must be between 1 and 10"
        
        # Validate source interface if provided
        if source_interface and not validate_interface_name(source_interface):
            return f"Invalid source interface: {source_interface}"
        
        # Build safe command
        args = ["-c", str(count)]
        if source_interface:
            args.extend(["-I", source_interface])
        args.append(destination)
        
        ping_command = build_safe_command("ping", args)
        
        # Execute command
        result = ssh_manager.execute_command(ping_command, server_name)
        
        if result['success']:
            output = f"Ping to {destination} from {result.get('server', 'current server')}\n"
            output += f"Exit code: {result['exit_code']}\n\n"
            output += result['stdout']
            
            # Try to parse with jc if available
            if result['exit_code'] == 0:
                try:
                    parsed = jc.parse('ping', result['stdout'])
                    if parsed:
                        output += f"\n\nParsed results:\n"
                        output += f"- Destination: {parsed.get('destination', 'N/A')}\n"
                        output += f"- Packets transmitted: {parsed.get('packets_transmitted', 'N/A')}\n"
                        output += f"- Packets received: {parsed.get('packets_received', 'N/A')}\n"
                        output += f"- Packet loss: {parsed.get('packet_loss_percent', 'N/A')}%\n"
                        if 'round_trip_ms_avg' in parsed:
                            output += f"- Average RTT: {parsed['round_trip_ms_avg']} ms\n"
                except Exception:
                    # If parsing fails, just return raw output
                    pass
            
            return output
        else:
            return f"Ping failed: {result['error']}"
    
    @mcp.tool()
    def traceroute(destination: str, server_name: str = None, max_hops: int = 30, source_interface: str = None) -> str:
        """Execute traceroute command with security validation
        
        Args:
            destination: Target host or IP to trace
            server_name: Optional server to run traceroute from
            max_hops: Maximum number of hops (default: 30, max: 64)
            source_interface: Optional source interface or IP
        """
        # Validate destination
        is_valid, error_msg = validate_destination(destination)
        if not is_valid:
            return f"Invalid destination: {error_msg}"
        
        # Validate max_hops
        if not isinstance(max_hops, int) or max_hops < 1 or max_hops > 64:
            return "Max hops must be between 1 and 64"
        
        # Validate source interface if provided
        if source_interface and not validate_interface_name(source_interface):
            return f"Invalid source interface: {source_interface}"
        
        # Build safe command
        args = ["-m", str(max_hops)]
        if source_interface:
            args.extend(["-i", source_interface])
        args.append(destination)
        
        traceroute_command = build_safe_command("traceroute", args)
        
        # Execute command
        result = ssh_manager.execute_command(traceroute_command, server_name)
        
        if result['success']:
            output = f"Traceroute to {destination} from {result.get('server', 'current server')}\n"
            output += f"Exit code: {result['exit_code']}\n\n"
            output += result['stdout']
            
            # Try to parse with jc if available
            try:
                parsed = jc.parse('traceroute', result['stdout'])
                if parsed and 'hops' in parsed:
                    output += f"\n\nParsed results:\n"
                    output += f"- Destination: {parsed.get('destination_name', 'N/A')} ({parsed.get('destination_ip', 'N/A')})\n"
                    output += f"- Total hops: {len(parsed['hops'])}\n"
                    
                    # Show last 3 hops
                    if parsed['hops']:
                        output += "- Last few hops:\n"
                        for hop in parsed['hops'][-3:]:
                            hop_num = hop.get('hop', '?')
                            probes = hop.get('probes', [])
                            if probes and probes[0]:
                                host = probes[0].get('hostname', probes[0].get('ip', 'Unknown'))
                                rtt = probes[0].get('rtt', 'N/A')
                                output += f"  Hop {hop_num}: {host} ({rtt} ms)\n"
            except Exception:
                # If parsing fails, just return raw output
                pass
            
            return output
        else:
            return f"Traceroute failed: {result['error']}"
    
    @mcp.tool() 
    def network_diagnostics(command_type: str, destination: str, server_name: str = None) -> str:
        """Run common network diagnostic commands (nslookup, dig, netstat, ss, ip)
        
        Args:
            command_type: Type of command (nslookup, dig, netstat, ss, ip)
            destination: Arguments for the command (e.g., hostname for nslookup)
            server_name: Optional server to run command from
        """
        # Whitelist of allowed diagnostic commands
        allowed_commands = {
            'nslookup': 'nslookup',
            'dig': 'dig',
            'netstat': 'netstat',
            'ss': 'ss',
            'ip': 'ip'
        }
        
        if command_type not in allowed_commands:
            return f"Invalid command type. Allowed: {', '.join(allowed_commands.keys())}"
        
        base_cmd = allowed_commands[command_type]
        
        # Validate and sanitize arguments based on command type
        if command_type in ['nslookup', 'dig']:
            # Validate destination for DNS queries
            is_valid, error_msg = validate_destination(destination)
            if not is_valid:
                return f"Invalid destination: {error_msg}"
            safe_args = [sanitize_command_argument(destination)]
        elif command_type == 'netstat':
            # Common netstat options
            allowed_netstat_args = ['-an', '-rn', '-i', '-s', '-tunlp', '-tulpn']
            if destination not in allowed_netstat_args:
                return f"Invalid netstat arguments. Allowed: {', '.join(allowed_netstat_args)}"
            safe_args = [destination]
        elif command_type == 'ss':
            # Common ss options
            allowed_ss_args = ['-an', '-tn', '-un', '-ln', '-s', '-i', '-tunlp']
            if destination not in allowed_ss_args:
                return f"Invalid ss arguments. Allowed: {', '.join(allowed_ss_args)}"
            safe_args = [destination]
        elif command_type == 'ip':
            # Common ip commands
            allowed_ip_args = ['addr', 'route', 'link', 'neigh']
            first_arg = destination.split()[0] if destination else ''
            if first_arg not in allowed_ip_args:
                return f"Invalid ip subcommand. Allowed: {', '.join(allowed_ip_args)}"
            safe_args = destination.split()[:2]  # Limit to subcommand and one option
        
        # Build command
        command = build_safe_command(base_cmd, safe_args)
        
        # Execute command
        result = ssh_manager.execute_command(command, server_name)
        
        if result['success']:
            output = f"{command_type} results from {result.get('server', 'current server')}\n"
            output += f"Command: {command}\n"
            output += f"Exit code: {result['exit_code']}\n\n"
            output += result['stdout']
            
            # Try to parse with jc if available and applicable
            if command_type in ['dig', 'netstat', 'ss'] and result['exit_code'] == 0:
                try:
                    # Map command type to jc parser name
                    parser_map = {
                        'dig': 'dig',
                        'netstat': 'netstat',
                        'ss': 'ss'
                    }
                    parser_name = parser_map.get(command_type)
                    if parser_name:
                        parsed = jc.parse(parser_name, result['stdout'])
                        if parsed:
                            output += f"\n\nParsed output available (JSON structure returned)"
                            # You could format specific fields here based on command type
                except Exception:
                    pass
            
            return output
        else:
            return f"{command_type} failed: {result['error']}"
    
    # Run the FastMCP server
    mcp.run()


if __name__ == "__main__":
    main()