# Multi-Server SSH MCP Server

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python-based Model Context Protocol (MCP) server that enables Claude to connect to and manage multiple SSH servers through a unified interface. Built with FastMCP, it provides secure, on-demand connections with comprehensive server management capabilities.

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

## Quick Start

### 1. Clone and Install

```bash
git clone <repository-url>
cd multi-ssh-mcp
pip install -r requirements.txt
```

Or using UV (recommended):
```bash
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

- Python 3.10 or higher
- SSH access to target servers
- SSH keys or passwords for authentication

### Dependencies

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

## Available Tools

### 1. `list_servers`
Lists all configured SSH servers with their details.

**Usage:** "List all available SSH servers"

### 2. `connect_server`
Connects to a specific SSH server.

**Parameters:**
- `server_name`: Name of the server to connect to

**Usage:** "Connect to the production server"

### 3. `disconnect_server`
Disconnects from the current SSH server.

**Usage:** "Disconnect from the current server"

### 4. `execute_command`
Executes a command on the current or specified server with optional output parsing.

**Parameters:**
- `command`: Command to execute
- `server_name` (optional): Server to connect to and execute on
- `parse_output` (optional): Control output parsing
  - `None` (default): Auto-parse common commands (ls, ps, df, etc.)
  - `True`: Force parsing if parser available
  - `False`: Disable parsing, return raw output only

**Usage:** 
- "Execute 'ls -la' on the current server"
- "Run 'systemctl status nginx' on the web-server-1"
- "Execute 'ps aux' with parse_output=True"

### 5. `upload_file`
Uploads a file to the current or specified server.

**Parameters:**
- `local_path`: Path to local file
- `remote_path`: Path on remote server
- `server_name` (optional): Server to upload to

**Usage:** "Upload /local/config.txt to /etc/app/config.txt on staging server"

### 6. `download_file`
Downloads a file from the current or specified server.

**Parameters:**
- `remote_path`: Path on remote server
- `local_path`: Local destination path
- `server_name` (optional): Server to download from

**Usage:** "Download /var/log/app.log from production to ./logs/"

### 7. `get_current_connection`
Shows information about the current SSH connection.

**Usage:** "What server am I currently connected to?"

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

- Store sensitive credentials in environment variables, not in the JSON config
- Use SSH keys instead of passwords when possible
- Limit SSH key permissions and use dedicated keys for automation
- Keep your configuration file secure (proper file permissions)
- Consider using SSH agent for key management

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

## License

MIT License - feel free to modify and use as needed.