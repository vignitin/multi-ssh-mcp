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
import re
from pathlib import Path
from typing import Any, Dict, Optional, List
import logging

import paramiko
from fastmcp import FastMCP

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
        self.load_config()
    
    def load_config(self):
        """Load server configurations from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                self.servers_config = config.get('ssh_servers', {})
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
    
    def execute_command(self, command: str, server_name: str = None) -> Dict[str, Any]:
        """Execute command on current or specified server"""
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
            
            return {
                'success': True,
                'server': self.current_server,
                'command': command,
                'exit_code': exit_code,
                'stdout': stdout_data,
                'stderr': stderr_data
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Command execution failed: {str(e)}"
            }
    
    def upload_file(self, local_path: str, remote_path: str, server_name: str = None) -> Dict[str, Any]:
        """Upload file to current or specified server"""
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
    
    # NETWORK TROUBLESHOOTING WORKFLOW:
    # 1. For any network/connectivity issues: Start with get_current_connection
    # 2. For connectivity/reachability: Use troubleshoot_app_connectivity_ping (primary tool)
    # 3. For path tracing/topology: Use troubleshoot_app_connectivity_trace_path (secondary tool)
    # 4. For packet size issues: Use troubleshoot_app_connectivity_discover_path_mtu (tertiary tool)
    
    @mcp.tool()
    def list_servers() -> str:
        """List all configured SSH servers with their details"""
        servers = ssh_manager.get_server_list()
        if not servers:
            return
        
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
    def execute_command(command: str, server_name: str = None) -> str:
        """Execute a command on the current or specified SSH server
        
        Args:
            command: Command to execute
            server_name: Optional server to connect to and execute command on
        """
        result = ssh_manager.execute_command(command, server_name)
        
        if result['success']:
            output = f"Command executed on {result['server']}: {result['command']}\n"
            output += f"Exit code: {result['exit_code']}\n\n"
            
            if result['stdout']:
                output += f"STDOUT:\n{result['stdout']}\n"
            
            if result['stderr']:
                output += f"STDERR:\n{result['stderr']}\n"
            
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
    def troubleshoot_app_connectivity_ping(server_name: str, destination: str, destination_name: str = None, source_interface: str = None) -> str:
        """Test basic network connectivity, reachability, and communication using ping.
        
        PRIMARY USE: Use this tool for any connectivity, reachability, or communication issues.
        This is the FIRST tool to use when troubleshooting network problems.
        
        FABRIC/DC NETWORK REQUIREMENT: When user mentions "network", "fabric", "DC", "data center", 
        "intra-DC", "inter-DC", or similar keywords, ALWAYS use the fabric interface IP address 
        (connected to DC network) from server description as source_interface parameter.
        DO NOT use management interfaces (100.123.0.0/16 subnet).
        
        Args:
            server_name: Name of the SSH server from which to run the ping command
            destination: Destination IP address, hostname, or DNS name to ping
            destination_name: Optional descriptive name for the destination for correlation purposes
            source_interface: Optional fabric interface IP or interface name to use as source for ping
        
        Returns:
            JSON structure with ping results and LLM formatting instructions
        """
        # Connect to the specified server
        connect_result = ssh_manager.connect(server_name)
        if not connect_result['success']:
            return json.dumps({
                "success": False,
                "error": f"Failed to connect to source server '{server_name}': {connect_result['error']}",
                "source_server": server_name,
                "destination": destination,
                "destination_name": destination_name,
                "source_interface": source_interface
            }, indent=2)
        
        # Get source server information
        source_config = ssh_manager.servers_config[server_name]
        
        # Execute ping command with 5 packets
        if source_interface:
            # Use source interface for fabric connectivity testing
            ping_command = f"ping -c 5 -I {source_interface} {destination}"
        else:
            # Standard ping without source interface specification
            ping_command = f"ping -c 5 {destination}"
            
        ping_result = ssh_manager.execute_command(ping_command)
        
        if not ping_result['success']:
            return json.dumps({
                "success": False,
                "error": f"Failed to execute ping command: {ping_result['error']}",
                "source_server": server_name,
                "source_host": source_config['host'],
                "destination": destination,
                "destination_name": destination_name,
                "command": ping_command
            }, indent=2)
        
        # Parse ping output
        stdout = ping_result['stdout']
        stderr = ping_result['stderr']
        
        # Initialize result structure
        result = {
            "success": True,
            "source_server": server_name,
            "source_host": source_config['host'],
            "source_interface": source_interface,
            "destination": destination,
            "destination_name": destination_name or destination,
            "command": ping_command,
            "exit_code": ping_result['exit_code']
        }
        
        # Extract destination IP from ping output
        ip_match = re.search(r'PING .+ \(([0-9.]+)\)', stdout)
        if ip_match:
            result["destination_ip"] = ip_match.group(1)
        else:
            result["destination_ip"] = "Unknown"
        
        # Determine if ping was successful (100% packet return)
        if ping_result['exit_code'] == 0:
            # Parse packet loss
            loss_match = re.search(r'(\d+)% packet loss', stdout)
            if loss_match:
                packet_loss = int(loss_match.group(1))
                result["ping_success"] = packet_loss == 0
                result["packet_loss_percent"] = packet_loss
            else:
                result["ping_success"] = False
                result["packet_loss_percent"] = 100
            
            # Parse statistics
            stats_match = re.search(r'(\d+) packets transmitted, (\d+) (?:packets )?received', stdout)
            if stats_match:
                result["packets_transmitted"] = int(stats_match.group(1))
                result["packets_received"] = int(stats_match.group(2))
            
            # Parse round-trip time statistics
            rtt_match = re.search(r'round-trip min/avg/max/stddev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms', stdout)
            if rtt_match:
                result["rtt_stats"] = {
                    "min_ms": float(rtt_match.group(1)),
                    "avg_ms": float(rtt_match.group(2)),
                    "max_ms": float(rtt_match.group(3)),
                    "stddev_ms": float(rtt_match.group(4))
                }
            else:
                # Try alternative format (some systems use different format)
                rtt_match2 = re.search(r'min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms', stdout)
                if rtt_match2:
                    result["rtt_stats"] = {
                        "min_ms": float(rtt_match2.group(1)),
                        "avg_ms": float(rtt_match2.group(2)),
                        "max_ms": float(rtt_match2.group(3)),
                        "mdev_ms": float(rtt_match2.group(4))
                    }
        else:
            # Ping failed
            result["ping_success"] = False
            result["packet_loss_percent"] = 100
            result["packets_transmitted"] = 5
            result["packets_received"] = 0
        
        # Include raw output for debugging if needed
        result["raw_output"] = {
            "stdout": stdout,
            "stderr": stderr
        }
        
        # Add summary message
        if result["ping_success"]:
            summary = f"✅ PING SUCCESS: {result['source_server']} → {result['destination_name']} ({result['destination_ip']})"
            if "rtt_stats" in result:
                summary += f" | Avg RTT: {result['rtt_stats']['avg_ms']:.1f}ms"
        else:
            summary = f"❌ PING FAILED: {result['source_server']} → {result['destination_name']} ({result['destination_ip']}) | {result['packet_loss_percent']}% packet loss"
        
        result["summary"] = summary
        
        # Add compact LLM formatting instructions
        ping_report_prompt = """

---

## 🏓 LLM INSTRUCTION: FORMAT AS PING CONNECTIVITY REPORT

**DIRECTIVE:** Format the above ping data as a professional markdown report with emojis and diagnostics.
**CONCISENESS:** Show ALL key information but keep text CONCISE. Use bullet points, tables, and clear sections. Avoid lengthy explanations.

### NETWORK CONNECTIVITY PING REPORT

#### 📡 CONNECTION OVERVIEW
- **Source:** [server_name] ([source_host])
- **Source Interface:** [source_interface if used, else "Default"]
- **Destination:** [destination_name] ([destination_ip])
- **Status:** [✅ Success / ❌ Failed]

#### 📊 RESULTS TABLE
| Metric | Value | Status |
|--------|-------|--------|
| Packets Transmitted | [number] | ✅/❌ |
| Packets Received | [number] | ✅/❌ |
| Packet Loss | [%] | 🟢/🟡/🔴 |

#### ⏱️ LATENCY (if available)
- **Min/Avg/Max RTT:** [values] ms
- **Quality:** 🟢 <10ms | 🟡 10-50ms | 🟠 50-100ms | 🔴 >100ms

#### 🔍 DIAGNOSTICS
- **Assessment:** Based on latency and packet loss
- **Recommendations:** Troubleshooting steps if failed
- **Fabric Note:** For any connectivity related queries that relates to Fabric, DC Network, Inter or between DCs, the tests should be run from the fabric interface IP of the source server and strictly not using the management interface (100.123.0.0/16 subnet). Check server description for fabric IPs.
- **Further Troubleshooting:** After completing ping analysis, ALWAYS ask the user: "Would you like to perform further network troubleshooting to trace the path through the network topology?" Do not mention specific tool names.

**FORMATTING:** Use emojis, bold headers, proper tables. Show source interface when used for fabric testing. Keep explanations brief and actionable.

---
"""
        
        return json.dumps(result, indent=2) + ping_report_prompt

    @mcp.tool()
    def troubleshoot_app_connectivity_trace_path(server_name: str, destination: str, destination_name: str = None, source_interface: str = None) -> str:
        """Trace network path and topology using traceroute to analyze routing and identify network devices.
        
        USAGE: Use this tool ONLY when user specifically asks for tracing paths, topology analysis, or routing investigation.
        This is the SECOND tool in the troubleshooting workflow after basic connectivity testing.
        
        FABRIC/DC NETWORK REQUIREMENT: When user mentions "network", "fabric", "DC", "data center", 
        "intra-DC", "inter-DC", or similar keywords, ALWAYS use the fabric interface IP address 
        (connected to DC network) from server description as source_interface parameter.
        DO NOT use management interfaces (100.123.0.0/16 subnet).
        
        Args:
            server_name: Name of the SSH server from which to run the traceroute command
            destination: Destination IP address, hostname, or DNS name to trace
            destination_name: Optional descriptive name for the destination for correlation purposes
            source_interface: Optional fabric interface IP (REQUIRED for fabric/DC network analysis) or interface name to use as source
        
        Returns:
            JSON structure with traceroute results and detailed LLM formatting instructions for network analysis
        """
        # Connect to the specified server
        connect_result = ssh_manager.connect(server_name)
        if not connect_result['success']:
            return json.dumps({
                "success": False,
                "error": f"Failed to connect to source server '{server_name}': {connect_result['error']}",
                "source_server": server_name,
                "destination": destination,
                "destination_name": destination_name,
                "source_interface": source_interface
            }, indent=2)
        
        # Get source server information
        source_config = ssh_manager.servers_config[server_name]
        
        # Execute traceroute command (always use traceroute for consistency)
        if source_interface:
            # Use source interface for fabric connectivity testing with traceroute
            trace_command = f"traceroute -i {source_interface} {destination}"
        else:
            # Standard traceroute without source interface specification
            trace_command = f"traceroute {destination}"
            
        trace_result = ssh_manager.execute_command(trace_command)
        
        if not trace_result['success']:
            return json.dumps({
                "success": False,
                "error": f"Failed to execute traceroute command: {trace_result['error']}",
                "source_server": server_name,
                "source_host": source_config['host'],
                "destination": destination,
                "destination_name": destination_name,
                "command": trace_command,
                "tool_used": "traceroute"
            }, indent=2)
        
        # Parse tracepath/traceroute output
        stdout = trace_result['stdout']
        stderr = trace_result['stderr']
        
        # Initialize result structure
        result = {
            "success": True,
            "source_server": server_name,
            "source_host": source_config['host'],
            "source_interface": source_interface,
            "destination": destination,
            "destination_name": destination_name or destination,
            "command": trace_command,
            "tool_used": "traceroute",
            "exit_code": trace_result['exit_code']
        }
        
        # Extract destination IP from traceroute output
        ip_match = re.search(r'traceroute to .+ \(([0-9.]+)\)', stdout)
        if ip_match:
            result["destination_ip"] = ip_match.group(1)
        else:
            # Try alternative format
            lines = stdout.split('\n')
            if lines and 'traceroute' in lines[0]:
                # Extract IP from first line
                ip_search = re.search(r'\(([0-9.]+)\)', lines[0])
                if ip_search:
                    result["destination_ip"] = ip_search.group(1)
                else:
                    result["destination_ip"] = "Unknown"
            else:
                result["destination_ip"] = "Unknown"
        
        # Parse traceroute hops
        hops = []
        hop_lines = stdout.split('\n')[1:]  # Skip first line (header)
        
        for line in hop_lines:
            line = line.strip()
            if not line or line.startswith('traceroute'):
                continue
                
            # Parse hop line (format: "1  router1.example.com (192.168.1.1)  1.234 ms  1.567 ms  1.890 ms")
            hop_match = re.match(r'^\s*(\d+)\s+(.+)', line)
            if hop_match:
                hop_num = int(hop_match.group(1))
                hop_data = hop_match.group(2).strip()
                
                # Extract hostname/IP and timings
                if '*' in hop_data:
                    # Timeout hop
                    hops.append({
                        "hop": hop_num,
                        "hostname": "* * *",
                        "ip": "Timeout",
                        "avg_rtt": None,
                        "status": "timeout"
                    })
                else:
                    # Parse hostname and IP
                    host_ip_match = re.search(r'(\S+)\s+\(([0-9.]+)\)', hop_data)
                    if host_ip_match:
                        hostname = host_ip_match.group(1)
                        ip = host_ip_match.group(2)
                    else:
                        # Try IP only format
                        ip_only_match = re.search(r'([0-9.]+)', hop_data)
                        if ip_only_match:
                            hostname = ip_only_match.group(1)
                            ip = ip_only_match.group(1)
                        else:
                            hostname = "Unknown"
                            ip = "Unknown"
                    
                    # Extract timing values
                    time_matches = re.findall(r'([0-9.]+)\s*ms', hop_data)
                    if time_matches:
                        times = [float(t) for t in time_matches]
                        avg_rtt = sum(times) / len(times)
                        status = "success"
                    else:
                        avg_rtt = None
                        status = "unknown"
                    
                    hops.append({
                        "hop": hop_num,
                        "hostname": hostname,
                        "ip": ip,
                        "avg_rtt": round(avg_rtt, 3) if avg_rtt else None,
                        "status": status
                    })
        
        result["hops"] = hops
        result["total_hops"] = len(hops)
        
        # Determine tracepath/traceroute success
        if trace_result['exit_code'] == 0:
            # Check if we reached the destination
            if hops and hops[-1]["ip"] == result.get("destination_ip"):
                result["traceroute_success"] = True
                result["reached_destination"] = True
            else:
                # Check if any hop matches destination
                reached = any(hop["ip"] == result.get("destination_ip") for hop in hops)
                result["traceroute_success"] = reached
                result["reached_destination"] = reached
        else:
            result["traceroute_success"] = False
            result["reached_destination"] = False
        
        # Calculate path statistics
        successful_hops = [hop for hop in hops if hop["status"] == "success" and hop["avg_rtt"]]
        if successful_hops:
            rtts = [hop["avg_rtt"] for hop in successful_hops]
            result["path_stats"] = {
                "min_rtt": min(rtts),
                "max_rtt": max(rtts),
                "avg_rtt": sum(rtts) / len(rtts),
                "successful_hops": len(successful_hops),
                "timeout_hops": len([hop for hop in hops if hop["status"] == "timeout"])
            }
        
        # Include raw output for debugging if needed
        result["raw_output"] = {
            "stdout": stdout,
            "stderr": stderr
        }
        
        # Add summary message
        if result["traceroute_success"]:
            summary = f"✅ TRACEROUTE SUCCESS: {result['source_server']} → {result['destination_name']} ({result['destination_ip']}) | {result['total_hops']} hops"
            if "path_stats" in result:
                summary += f" | Avg RTT: {result['path_stats']['avg_rtt']:.1f}ms"
        else:
            summary = f"❌ TRACEROUTE FAILED: {result['source_server']} → {result['destination_name']} ({result['destination_ip']}) | {result['total_hops']} hops traced"
        
        result["summary"] = summary
        
        # Add comprehensive LLM formatting instructions with network analysis guidance
        traceroute_report_prompt = """

---

## 🛤️ LLM INSTRUCTION: FORMAT AS COMPREHENSIVE NETWORK PATH ANALYSIS REPORT

**DIRECTIVE:** Format the above traceroute data as a professional markdown report with detailed network analysis and device correlation.
**CONCISENESS:** Show ALL key information but keep text CONCISE. Use bullet points, tables, and clear sections. Avoid lengthy explanations.

### NETWORK PATH ANALYSIS REPORT

#### 📡 CONNECTION OVERVIEW
- **Source:** [server_name] ([source_host])
- **Source Interface:** [source_interface if used, else "Default"]
- **Destination:** [destination_name] ([destination_ip])
- **Tool Used:** traceroute
- **Status:** [✅ Success / ❌ Failed]
- **Total Hops:** [number]

#### 🛤️ DETAILED NETWORK PATH TABLE
| Hop | Hostname/IP | RTT (ms) | Status | Analysis |
|-----|-------------|----------|--------|----------|
| [hop] | [hostname] ([ip]) | [avg_rtt] | ✅/⏸️/❌ | [latency analysis] |

#### ⏱️ PATH PERFORMANCE STATISTICS
- **Min/Avg/Max RTT:** [values] ms
- **Successful Hops:** [number] / [total]
- **Timeout Hops:** [number] (identify potential filtering points)
- **Path Quality:** 🟢 <50ms avg | 🟡 50-100ms | 🟠 100-200ms | 🔴 >200ms

#### 🔍 COMPREHENSIVE NETWORK ANALYSIS
**CRITICAL LLM ANALYSIS REQUIREMENTS:**

1. **Hop-by-Hop Analysis:**
   - Identify latency jumps > 20ms between consecutive hops
   - Flag timeout hops (* * *) as potential network device issues
   - Correlate hop IPs with network topology

2. **Problem Identification:**
   - **Last Successful Hop:** Identify the last responsive hop before failures
   - **Network Segment Analysis:** Determine which network segment (access, aggregation, core, WAN) shows issues
   - **Device Correlation:** If possible, correlate hop IPs with known network devices

3. **Fabric/DC Network Context:**
   - If fabric keywords detected, focus on intra-DC or inter-DC path analysis
   - Identify spine/leaf topology patterns in hop progression
   - Flag management network usage if source_interface not used for fabric queries

4. **Actionable Recommendations:**
   - Suggest specific network devices to investigate based on problematic hops
   - Recommend using Apstra tools if network device information is needed
   - Provide next-step troubleshooting actions based on analysis

5. **Integration Guidance:**
   - If network device details needed: "Use available Apstra tools to get device information for IP [problematic_hop_ip]"
   - Correlate findings with connectivity tests and suggest complementary analysis

6. **MTU Analysis Suggestion:**
   - After completing path analysis, ALWAYS ask the user: "Would you like to discover the Path MTU to identify any packet size limitations that could affect performance?"
   - MTU discovery can identify packet size bottlenecks that may cause fragmentation or dropped packets
   - Particularly important for fabric/DC networks that should support jumbo frames (9000 bytes)
   - Do not mention tool names, just suggest checking the maximum packet size supported by the network path

**FORMATTING:** Use emojis (✅ success, ⏸️ timeout, ❌ failed, 🚨 critical issue), bold headers, detailed analysis tables. Keep explanations brief and actionable.

**NETWORK TROUBLESHOOTING FOCUS:** Provide specific, actionable insights about WHERE in the network path issues occur and WHICH devices to investigate. Compare results with Apstra tools for device correlation and suggest further investigation if needed.


---
"""
        
        return json.dumps(result, indent=2) + traceroute_report_prompt

    @mcp.tool()
    def troubleshoot_app_connectivity_discover_path_mtu(server_name: str, destination: str, destination_name: str = None, source_interface: str = None, start_mtu: int = 1500, min_mtu: int = 576) -> str:
        """Discover Path MTU (Maximum Transmission Unit) between source and destination using ping with DF flag.
        
        Uses binary search approach with ping -M do (Don't Fragment) to find the largest packet size
        that can traverse the network path without fragmentation. Essential for diagnosing packet
        size related connectivity issues, especially in fabric/DC networks with varying MTU sizes.
        
        FABRIC/DC NETWORK REQUIREMENT: When user mentions "network", "fabric", "DC", "data center", 
        "intra-DC", "inter-DC", or similar keywords, ALWAYS use the fabric interface IP address 
        (connected to DC network) from server description as source_interface parameter.
        DO NOT use management interfaces (100.123.0.0/16 subnet).
        
        Args:
            server_name: Name of the SSH server from which to run the MTU discovery
            destination: Destination IP address, hostname, or DNS name to test MTU
            destination_name: Optional descriptive name for the destination for correlation purposes
            source_interface: Optional fabric interface IP (REQUIRED for fabric/DC network analysis) or interface name to use as source
            start_mtu: Starting MTU size for discovery (default: 1500 bytes)
            min_mtu: Minimum MTU size to test (default: 576 bytes - IPv4 minimum)
        
        Returns:
            JSON structure with Path MTU discovery results and detailed LLM formatting instructions
        """
        # Connect to the specified server
        connect_result = ssh_manager.connect(server_name)
        if not connect_result['success']:
            return json.dumps({
                "success": False,
                "error": f"Failed to connect to source server '{server_name}': {connect_result['error']}",
                "source_server": server_name,
                "destination": destination,
                "destination_name": destination_name,
                "source_interface": source_interface
            }, indent=2)
        
        # Get source server information
        source_config = ssh_manager.servers_config[server_name]
        
        # Initialize result structure
        result = {
            "success": True,
            "source_server": server_name,
            "source_host": source_config['host'],
            "source_interface": source_interface,
            "destination": destination,
            "destination_name": destination_name or destination,
            "start_mtu": start_mtu,
            "min_mtu": min_mtu,
            "mtu_tests": [],
            "discovered_path_mtu": None
        }
        
        # Test initial connectivity with small packet to verify reachability
        if source_interface:
            initial_ping_cmd = f"ping -c 1 -s 56 -I {source_interface} {destination}"
        else:
            initial_ping_cmd = f"ping -c 1 -s 56 {destination}"
        
        initial_result = ssh_manager.execute_command(initial_ping_cmd)
        
        if not initial_result['success'] or initial_result['exit_code'] != 0:
            return json.dumps({
                "success": False,
                "error": f"Initial connectivity test failed. Cannot proceed with MTU discovery.",
                "source_server": server_name,
                "source_host": source_config['host'],
                "destination": destination,
                "destination_name": destination_name,
                "initial_ping_command": initial_ping_cmd,
                "initial_ping_output": initial_result.get('stdout', ''),
                "initial_ping_error": initial_result.get('stderr', '')
            }, indent=2)
        
        # Extract destination IP from initial ping
        stdout = initial_result['stdout']
        ip_match = re.search(r'PING .+ \(([0-9.]+)\)', stdout)
        if ip_match:
            result["destination_ip"] = ip_match.group(1)
        else:
            result["destination_ip"] = "Unknown"
        
        # Binary search for Path MTU
        max_mtu = start_mtu
        min_working_mtu = min_mtu
        discovered_mtu = min_mtu
        
        # First, test if the starting MTU works
        current_test_size = start_mtu - 28  # Subtract IP (20) + ICMP (8) headers
        
        while min_working_mtu <= max_mtu:
            # Calculate packet size (subtract headers: IP=20, ICMP=8)
            packet_size = current_test_size
            
            # Build ping command with Don't Fragment flag
            if source_interface:
                ping_cmd = f"ping -c 1 -M do -s {packet_size} -I {source_interface} {destination}"
            else:
                ping_cmd = f"ping -c 1 -M do -s {packet_size} {destination}"
            
            ping_result = ssh_manager.execute_command(ping_cmd)
            
            test_record = {
                "mtu_size": current_test_size + 28,  # Add headers back for reporting
                "packet_size": packet_size,
                "command": ping_cmd,
                "exit_code": ping_result.get('exit_code', -1),
                "success": False,
                "error_message": None
            }
            
            if ping_result['success'] and ping_result['exit_code'] == 0:
                # Ping succeeded
                test_record["success"] = True
                discovered_mtu = current_test_size + 28
                min_working_mtu = current_test_size + 28 + 1
            else:
                # Ping failed - likely due to MTU size
                test_record["success"] = False
                stderr_output = ping_result.get('stderr', '')
                stdout_output = ping_result.get('stdout', '')
                
                # Check for specific MTU-related error messages
                if "Message too long" in stderr_output or "Frag needed" in stderr_output:
                    test_record["error_message"] = "Packet too large (MTU exceeded)"
                elif "Network is unreachable" in stderr_output:
                    test_record["error_message"] = "Network unreachable"
                elif "Destination Host Unreachable" in stdout_output:
                    test_record["error_message"] = "Destination unreachable"
                else:
                    test_record["error_message"] = f"Ping failed: {stderr_output.strip() or 'Unknown error'}"
                
                max_mtu = current_test_size + 28 - 1
            
            result["mtu_tests"].append(test_record)
            
            # Binary search logic
            if min_working_mtu > max_mtu:
                break
            
            current_test_size = ((min_working_mtu + max_mtu) // 2) - 28
            
            # Prevent infinite loop
            if len(result["mtu_tests"]) > 15:  # Reasonable limit for binary search
                break
        
        result["discovered_path_mtu"] = discovered_mtu
        result["total_tests"] = len(result["mtu_tests"])
        
        # Analyze MTU result
        if discovered_mtu >= 9000:
            mtu_category = "Jumbo Frame"
            mtu_status = "excellent"
        elif discovered_mtu >= 1500:
            mtu_category = "Standard Ethernet"
            mtu_status = "good"
        elif discovered_mtu >= 1476:
            mtu_category = "VLAN Tagged"
            mtu_status = "acceptable"
        elif discovered_mtu >= 1200:
            mtu_category = "Reduced MTU"
            mtu_status = "suboptimal"
        else:
            mtu_category = "Fragmented Path"
            mtu_status = "problematic"
        
        result["mtu_analysis"] = {
            "category": mtu_category,
            "status": mtu_status,
            "is_optimal": discovered_mtu >= 1500
        }
        
        # Add summary message
        summary = f"🔍 MTU DISCOVERY: {result['source_server']} → {result['destination_name']} ({result['destination_ip']}) | Path MTU: {discovered_mtu} bytes ({mtu_category})"
        result["summary"] = summary
        
        # Add comprehensive LLM formatting instructions
        mtu_report_prompt = """

---

## 📏 LLM INSTRUCTION: FORMAT AS PATH MTU DISCOVERY REPORT

**DIRECTIVE:** Format the above MTU discovery data as a professional markdown report with detailed analysis and recommendations.
**CONCISENESS:** Show ALL key information but keep text CONCISE. Use bullet points, tables, and clear sections. Avoid lengthy explanations.

### PATH MTU DISCOVERY REPORT

#### 📡 CONNECTION OVERVIEW
- **Source:** [server_name] ([source_host])
- **Source Interface:** [source_interface if used, else "Default"]
- **Destination:** [destination_name] ([destination_ip])
- **Discovered Path MTU:** [discovered_path_mtu] bytes
- **MTU Category:** [mtu_category] ([mtu_status])
- **Tests Performed:** [total_tests]

#### 📊 MTU TEST RESULTS TABLE
| MTU Size | Packet Size | Result | Error Message |
|----------|-------------|--------|---------------|
| [mtu_size] bytes | [packet_size] bytes | ✅/❌ | [error_message if failed] |

#### 📏 MTU ANALYSIS
- **Path MTU:** [discovered_path_mtu] bytes
- **Category:** [mtu_category]
- **Status:** 🟢 Excellent (≥9000) | 🟡 Good (≥1500) | 🟠 Acceptable (≥1476) | 🔴 Problematic (<1200)
- **Optimization:** [is_optimal: "Optimal" / "Needs optimization"]

#### 🔍 DETAILED ANALYSIS
**CRITICAL LLM ANALYSIS REQUIREMENTS:**

1. **MTU Bottleneck Identification:**
   - Identify the constraining factor in the network path
   - Correlate with previous traceroute results if available
   - Highlight any unexpected MTU limitations

2. **Network Segment Analysis:**
   - **Fabric/DC Networks:** Expected 9000-byte jumbo frames
   - **WAN/Internet:** Typically 1500-byte standard MTU
   - **VLAN Networks:** Often 1476-byte due to VLAN tags
   - **VPN/Tunnels:** Reduced MTU due to encapsulation overhead

3. **Performance Impact Assessment:**
   - **High MTU (≥9000):** Excellent for bulk data transfer, minimal fragmentation
   - **Standard MTU (1500):** Good for most applications
   - **Low MTU (<1200):** May cause performance issues, excessive fragmentation

4. **Actionable Recommendations:**
   - Application configuration suggestions based on discovered MTU
   - Network optimization recommendations
   - Investigation steps for suboptimal MTU

5. **Integration with Previous Tests:**
   - Correlate MTU findings with ping/traceroute issues
   - Identify if packet size contributes to connectivity problems
   - Suggest retesting ping/traceroute with optimal packet sizes

#### 🛠️ RECOMMENDATIONS
- **Application Tuning:** Configure applications to use discovered MTU
- **Network Investigation:** If MTU is unexpectedly low, investigate intermediate devices
- **Performance Optimization:** Use jumbo frames if path supports 9000-byte MTU
- **Fabric Testing:** For fabric networks, verify jumbo frame configuration

**FORMATTING:** Use emojis (✅ success, ❌ failed, 🟢/🟡/🟠/🔴 status), bold headers, detailed analysis tables. Keep explanations brief and actionable.

**TROUBLESHOOTING FOCUS:** Provide specific insights about network path MTU constraints and their impact on application performance.

---
"""
        
        return json.dumps(result, indent=2) + mtu_report_prompt

    # Run the FastMCP server
    mcp.run()


if __name__ == "__main__":
    main()