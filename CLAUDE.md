# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Multi-Server SSH MCP (Model Context Protocol) server built using FastMCP framework. It allows Claude to connect to and manage multiple SSH servers defined in a JSON configuration file, with support for command execution, file transfers, and connection management.

## Key Commands

### Running the MCP Server
```bash
# Run with default config (ssh_servers.json)
python3 multi_ssh_mcp.py

# Run with UV (recommended)
uv run multi_ssh_mcp.py

# Specify custom config file
python3 multi_ssh_mcp.py /path/to/config.json
python3 multi_ssh_mcp.py --config servers.json
```

### Development Commands
```bash
# Install dependencies
pip install fastmcp paramiko

# With UV
uv add fastmcp paramiko

# Run linting (if configured)
ruff check .
black --check .

# Run tests (if test files exist)
pytest
```

## Architecture

### Core Components

**SSHServerManager Class** (`multi_ssh_mcp.py:28`)
- Manages SSH connections to multiple servers
- Handles authentication (password and SSH key)
- Supports environment variable substitution for credentials
- Maintains single active connection (one server at a time)

**FastMCP Integration** (`multi_ssh_mcp.py:349`)
- Exposes 6 MCP tools for SSH operations
- Handles tool parameter validation and response formatting

### Configuration System

**Server Configuration** (`servers.json` or custom file)
- JSON structure with `ssh_servers` object
- Each server supports: host, port, username, auth_method, description, timeout
- Environment variable substitution: `${ENV:VARIABLE_NAME}`
- Two auth methods: "password" or "key"

### Available MCP Tools

1. `list_servers()` - Lists all configured servers
2. `connect_server(server_name)` - Connects to specific server
3. `disconnect_server()` - Disconnects current connection
4. `execute_command(command, server_name?)` - Runs commands
5. `upload_file(local_path, remote_path, server_name?)` - SFTP upload
6. `download_file(remote_path, local_path, server_name?)` - SFTP download
7. `get_current_connection()` - Shows current connection status

## Security Model

- Credentials stored in environment variables (not in config files)
- SSH key authentication preferred over passwords
- Auto-accepts host keys (uses `paramiko.AutoAddPolicy()`)
- Single connection model prevents connection sprawl

## Configuration Files

- `ssh_config_example.json` - Template showing all configuration options
- `servers.json` - Active server configuration (not in repo)
- `pyproject.toml` - Python project configuration with FastMCP dependencies

## Error Handling

Connection failures return structured error responses with specific error types:
- Authentication failures
- SSH connection errors  
- File not found errors
- Environment variable missing errors

## Development Notes

- Uses Python 3.10+ with FastMCP framework
- Paramiko library for SSH/SFTP operations
- Logging configured to INFO level
- Command-line argument parsing supports multiple config file methods