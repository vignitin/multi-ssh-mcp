# Multi-Server SSH MCP Server

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python-based Model Context Protocol (MCP) server that enables Claude to connect to and manage multiple SSH servers through a unified interface. Built with FastMCP, it provides secure, on-demand connections with comprehensive server management capabilities.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Docker Installation](#docker-installation-recommended)
  - [Local Installation](#local-installation)
- [Configuration](#configuration)
  - [Server Configuration](#server-configuration)
  - [Authentication Methods](#authentication-methods)
  - [Claude Desktop Setup](#claude-desktop-setup)
  - [Docker Setup](#docker-setup)
- [Available Tools](#available-tools)
  - [Core SSH Tools](#core-ssh-tools)
  - [Command Execution](#command-execution)
  - [File Transfer](#file-transfer)
  - [Network Diagnostics](#network-diagnostics)
- [Output Parsing with JC](#output-parsing-with-jc)
- [Usage Examples](#usage-examples)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Logging](#logging)
- [Environment Variables](#environment-variables)
- [SSE/HTTP Mode](#ssehttp-mode)
  - [Running in SSE Mode](#running-in-sse-mode)
  - [HTTP Endpoints](#http-endpoints)
  - [Client Integration](#client-integration)
- [License](#license)

## Features

- **Multiple Server Support**: Define unlimited SSH servers in JSON configuration
- **On-Demand Connections**: Connects only when needed, one server at a time
- **Flexible Authentication**: Supports both password and SSH key authentication
- **Environment Variables**: Secure credential storage using environment variables
- **File Transfer**: Upload and download files via SFTP
- **Command Execution**: Execute commands on any configured server
- **Structured Output Parsing**: Automatic JSON parsing of command outputs using JC library
- **Connection Management**: Easy connect/disconnect with status tracking
- **Security First**: Credentials never stored in configuration files
- **Multiple Transports**: Supports both stdio (Claude Desktop) and SSE/HTTP modes
- **Docker Ready**: Full containerization with Docker and Docker Compose support

## Quick Start

### 1. Clone and Install

```bash
git clone <repository-url>
cd multi-ssh-mcp
```

Install dependencies (see [Installation](#installation) section for more options):
```bash
pip install -r requirements.txt
# or using UV (recommended)
uv sync
```

### 2. Create Configuration

Copy the example configuration and customize for your servers:
```bash
cp ssh_config_example.json servers.json
# Edit servers.json with your server details
```

### 3. Run the MCP Server

```bash
# Using default config (servers.json)
python3 multi_ssh_mcp.py

# Using UV
uv run multi_ssh_mcp.py

# With custom config
python3 multi_ssh_mcp.py --config my_servers.json
```

## Installation

### System Requirements

- Python 3.10 or higher (or Docker)
- SSH access to target servers
- SSH keys or passwords for authentication

### Docker Installation (Recommended)

Using Docker simplifies deployment and ensures consistent environments:

```bash
# Clone the repository
git clone <repository-url>
cd multi-ssh-mcp

# Build the Docker image
./scripts/build.sh

# Copy and configure your servers
cp ssh_config_example.json config/servers.json
# Edit config/servers.json with your server details
```

### Local Installation

Install from requirements.txt:
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install fastmcp>=2.0.0 paramiko>=3.0.0 jc>=1.25.0
```

### Development Dependencies

For development and testing:
```bash
pip install -e .[dev]
```

## Usage

### Command Line Options

```bash
# Use default config file (servers.json in current directory)
python3 multi_ssh_mcp.py

# Specify config file path as positional argument
python3 multi_ssh_mcp.py /path/to/my_servers.json

# Use --config flag
python3 multi_ssh_mcp.py --config /path/to/my_servers.json
python3 multi_ssh_mcp.py -c servers.json
```

### Help

```bash
python3 multi_ssh_mcp.py --help
```

## Configuration

### 1. Create Configuration File

Create your SSH servers configuration file (e.g., `my_servers.json`) with your server definitions. See the example configuration for the structure.

### 2. Authentication Methods

**Password Authentication:**
```json
{
  "host": "example.com",
  "username": "user",
  "auth_method": "password",
  "password": "${ENV:SERVER_PASSWORD}"
}
```

**SSH Key Authentication:**
```json
{
  "host": "example.com", 
  "username": "user",
  "auth_method": "key",
  "private_key_path": "~/.ssh/id_rsa",
  "key_passphrase": "${ENV:KEY_PASSPHRASE}"
}
```

### 3. Environment Variables

Set environment variables for secure credential storage (when using `${ENV:VAR_NAME}` in config):

```bash
export STAGING_PASSWORD="your_staging_password"
export PROD_KEY_PASSPHRASE="your_key_passphrase"
export BACKUP_PASSWORD="your_backup_password"
```

## Claude Desktop Integration

### Configuration

Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "Multi-SSH MCP Server": {
      "command": "uv",
      "args": [
        "run",
        "--with",
        "fastmcp,paramiko",
        "python3",
        "/path/to/multi-ssh-mcp/multi_ssh_mcp.py",
        "/path/to/multi-ssh-mcp/servers.json"
      ]
    }
  }
}
```

### Alternative Configurations

**Using Python directly (if dependencies are already installed):**
```json
{
  "mcpServers": {
    "Multi-SSH MCP Server": {
      "command": "python3",
      "args": [
        "/path/to/multi-ssh-mcp/multi_ssh_mcp.py",
        "/path/to/multi-ssh-mcp/servers.json"
      ]
    }
  }
}
```

**Using --config flag:**
```json
{
  "mcpServers": {
    "Multi-SSH MCP Server": {
      "command": "uv",
      "args": [
        "run",
        "--with",
        "fastmcp,paramiko",
        "python3",
        "/path/to/multi-ssh-mcp/multi_ssh_mcp.py",
        "--config",
        "/path/to/multi-ssh-mcp/servers.json"
      ]
    }
  }
}
```

**Using default config location (servers.json in script directory):**
```json
{
  "mcpServers": {
    "Multi-SSH MCP Server": {
      "command": "uv",
      "args": [
        "run",
        "--with",
        "fastmcp,paramiko",
        "python3",
        "/path/to/multi-ssh-mcp/multi_ssh_mcp.py"
      ]
    }
  }
}
```

> **Note:** Replace `/path/to/multi-ssh-mcp/` with the actual absolute path to your cloned repository.

### Docker Setup

The Multi-SSH MCP server can be run in Docker containers with support for both stdio (for Claude Desktop) and SSE/HTTP modes.

#### Quick Start with Docker

1. **Build the Docker image:**
   ```bash
   ./scripts/build.sh
   ```

2. **Run in stdio mode (for Claude Desktop):**
   ```bash
   ./scripts/run-docker.sh stdio
   ```

3. **Run in SSE/HTTP mode:**
   ```bash
   ./scripts/run-docker.sh sse
   # Server will be available at http://localhost:8080
   ```

#### Docker Compose Options

```bash
# Run in stdio mode
docker-compose --profile stdio run --rm mcp-ssh-stdio

# Run in SSE/HTTP mode
docker-compose --profile sse up -d

# Run in development mode with hot reload
docker-compose --profile dev up
```

#### Claude Desktop Configuration for Docker

Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "Multi-SSH MCP (Docker)": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/path/to/config:/config:ro",
        "-v", "${HOME}/.ssh:/home/mcp/.ssh:ro",
        "-e", "SSH_PASSWORD_PROD",
        "-e", "SSH_PASSWORD_STAGING",
        "multi-ssh-mcp:latest"
      ]
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| **list_servers** | Lists all configured SSH servers with their details |
| **connect_server** | Connects to a specific SSH server |
| **disconnect_server** | Disconnects from the current SSH server |
| **execute_command** | Executes commands with automatic output parsing (JC library) |
| **upload_file** | Uploads files via SFTP with path validation |
| **download_file** | Downloads files via SFTP with path validation |
| **get_current_connection** | Shows current SSH connection status |
| **ping** | Secure ping with count limits and source interface support |
| **traceroute** | Traceroute with hop control and automatic parsing |
| **network_diagnostics** | Run safe network commands (dig, nslookup, netstat, ss, ip) |

### Core SSH Tools

- `list_servers()`: Show all configured servers
- `connect_server(server_name)`: Connect to a specific server
- `disconnect_server()`: Close current connection
- `get_current_connection()`: Check connection status

### Command Execution

- `execute_command(command, server_name=None, parse_output=None)`: Run commands with JC parsing
  - Auto-parses common commands (ls, ps, df, netstat, etc.)
  - Optional parse_output: None (auto), True (force), False (disable)

### File Transfer

- `upload_file(local_path, remote_path, server_name=None)`: SFTP upload
- `download_file(remote_path, local_path, server_name=None)`: SFTP download

### Network Diagnostics

- `ping(destination, server_name=None, count=5, source_interface=None)`: Test connectivity
- `traceroute(destination, server_name=None, max_hops=30, source_interface=None)`: Trace network path
- `network_diagnostics(command_type, destination, server_name=None)`: Run network tools
  - Supported commands: nslookup, dig, netstat, ss, ip

## Output Parsing with JC

The MCP server automatically parses command outputs into structured JSON format using the JC library. This makes it easier to analyze and process command results.

### Automatic Parsing
Common commands like `ls`, `ps`, `df`, `netstat`, `ifconfig`, and many others are automatically parsed when executed.

### Parsing Control
Use the `parse_output` parameter in `execute_command`:
- `None` (default): Auto-parse supported commands
- `True`: Force parsing attempt
- `False`: Disable parsing, return raw output only

### Example
When running `df -h`, instead of raw text output, you'll receive structured JSON data with fields like `filesystem`, `size`, `used`, `available`, `use_percent`, and `mount_point`.

## Usage Examples

1. **List available servers:**
   ```
   "Show me all configured SSH servers"
   ```

2. **Connect and run commands:**
   ```
   "Connect to the production server and check disk usage"
   "Run 'ps aux | grep nginx' on web-server-1"
   ```

3. **File operations:**
   ```
   "Upload my local script.sh to /tmp/ on the staging server"
   "Download the nginx config from production server"
   ```

4. **Multi-server workflows:**
   ```
   "Check the system load on all web servers"
   "Deploy the config file to both staging and production"
   ```

## Security Considerations

### Built-in Security Features
- **Command Injection Prevention**: All user inputs are sanitized and validated
- **Path Validation**: File paths are checked for directory traversal attempts
- **Command Whitelisting**: Only safe commands are allowed in execute_command
- **Argument Sanitization**: Special characters and shell metacharacters are filtered
- **Network Input Validation**: IP addresses and hostnames are validated

### Best Practices
- Store sensitive credentials in environment variables, not in the JSON config
- Use SSH keys instead of passwords when possible
- Limit SSH key permissions and use dedicated keys for automation
- Keep your configuration file secure (proper file permissions)
- Consider using SSH agent for key management

### Security Restrictions
The following are blocked for security:
- Command chaining (&&, ||, ;)
- Shell redirections (>, <, |)
- Command substitution ($(), ``)
- Environment variable expansion (except for echo $VAR)
- Directory traversal in file paths (..)

## Troubleshooting

### Connection Issues
- Verify server hostnames and ports are correct
- Check that SSH keys exist and have proper permissions (`chmod 600`)
- Ensure environment variables are set correctly
- Test SSH connections manually first: `ssh user@host`

### Authentication Failures
- For key auth: verify the key path and passphrase
- For password auth: check the password in environment variables
- Ensure the SSH server accepts the authentication method

### Configuration Problems
- Validate JSON syntax in your config file
- Check file permissions on config and key files
- Verify the config file path is correct

## Logging

The server logs connection attempts and errors. To see detailed logs, run with:

```bash
python3 multi_ssh_mcp.py 2>&1 | tee ssh_mcp.log
```

## Environment Variables

The MCP server supports the following environment variables:

### Transport Configuration
- `MCP_TRANSPORT`: Transport mode (`stdio` or `sse`, default: `stdio`)
- `MCP_HOST`: Host for SSE mode (default: `0.0.0.0`)
- `MCP_PORT`: Port for SSE mode (default: `8080`)
- `MCP_CONFIG_PATH`: Path to servers.json file (default: `servers.json`)

### SSH Credentials
- `SSH_PASSWORD_<SERVER_NAME>`: Password for specific server
- `SSH_KEY_PASSPHRASE`: Passphrase for SSH keys
- Any custom variables referenced in your servers.json

### Docker-specific
- `PYTHONUNBUFFERED`: Set to `1` for immediate log output

## SSE/HTTP Mode

The Multi-SSH MCP server supports Server-Sent Events (SSE) for HTTP-based communication, making it accessible from web applications and HTTP clients.

### Running in SSE Mode

1. **Using Docker:**
   ```bash
   ./scripts/run-docker.sh sse
   # or
   docker-compose --profile sse up -d
   ```

2. **Local Python:**
   ```bash
   MCP_TRANSPORT=sse MCP_PORT=8080 python multi_ssh_mcp.py
   ```

### HTTP Endpoints

When running with `MCP_TRANSPORT=sse`, the server provides:

- `GET /sse` - Server-Sent Events stream for real-time MCP messages
- `POST /messages` - Send commands to the MCP server
- `GET /health` - Health check endpoint for monitoring

### Client Integration

#### JavaScript/TypeScript Example:
```javascript
// Connect to SSE endpoint
const eventSource = new EventSource('http://localhost:8080/sse');

// Handle incoming messages
eventSource.onmessage = (event) => {
    const message = JSON.parse(event.data);
    console.log('MCP Response:', message);
};

// Send MCP commands
async function sendCommand(method, params) {
    const response = await fetch('http://localhost:8080/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: method,
            params: params,
            id: Date.now()
        })
    });
    return response.json();
}

// Example: List servers
sendCommand('list_servers', {});
```

#### Python Client Example:
```python
import requests
import sseclient

# Connect to SSE stream
response = requests.get('http://localhost:8080/sse', stream=True)
client = sseclient.SSEClient(response)

# Send command
def send_command(method, params=None):
    return requests.post('http://localhost:8080/messages', json={
        'jsonrpc': '2.0',
        'method': method,
        'params': params or {},
        'id': 1
    }).json()

# Example usage
servers = send_command('list_servers')
print(servers)
```

### Use Cases for SSE Mode

- **Web Applications**: Build web UIs for SSH management
- **Microservices**: Integrate SSH operations into HTTP-based architectures
- **Monitoring Systems**: Stream real-time command outputs
- **API Gateways**: Expose SSH functionality through REST APIs

## License

MIT License - feel free to modify and use as needed.