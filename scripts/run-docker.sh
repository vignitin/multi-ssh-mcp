#!/bin/bash
set -e

# Script to run Multi-SSH MCP Server in Docker

# Default values
MODE="${1:-stdio}"
CONFIG_PATH="${CONFIG_PATH:-./config}"
SSH_PATH="${SSH_PATH:-$HOME/.ssh}"

# Ensure config directory exists
if [ ! -d "$CONFIG_PATH" ]; then
    echo "Error: Config directory not found at $CONFIG_PATH"
    echo "Please create it and add your servers.json file"
    exit 1
fi

# Check if servers.json exists
if [ ! -f "$CONFIG_PATH/servers.json" ]; then
    echo "Error: servers.json not found in $CONFIG_PATH"
    echo "Please create it from ssh_config_example.json"
    exit 1
fi

case "$MODE" in
    "stdio")
        echo "Running Multi-SSH MCP in stdio mode..."
        docker run -it --rm \
            -v "$CONFIG_PATH:/config:ro" \
            -v "$SSH_PATH:/home/mcp/.ssh:ro" \
            -e MCP_TRANSPORT=stdio \
            -e SSH_PASSWORD_PROD \
            -e SSH_PASSWORD_STAGING \
            -e SSH_KEY_PASSPHRASE \
            multi-ssh-mcp:latest
        ;;
    
    "sse"|"http")
        echo "Running Multi-SSH MCP in SSE/HTTP mode..."
        docker run -d --name multi-ssh-mcp \
            -p 8080:8080 \
            -v "$CONFIG_PATH:/config:ro" \
            -v "$SSH_PATH:/home/mcp/.ssh:ro" \
            -e MCP_TRANSPORT=sse \
            -e SSH_PASSWORD_PROD \
            -e SSH_PASSWORD_STAGING \
            -e SSH_KEY_PASSPHRASE \
            --restart unless-stopped \
            multi-ssh-mcp:latest
        
        echo "Server started on http://localhost:8080"
        echo "To view logs: docker logs -f multi-ssh-mcp"
        echo "To stop: docker stop multi-ssh-mcp && docker rm multi-ssh-mcp"
        ;;
    
    "dev")
        echo "Running Multi-SSH MCP in development mode..."
        docker-compose --profile dev up
        ;;
    
    *)
        echo "Usage: $0 [stdio|sse|http|dev]"
        echo "  stdio - Run in stdio mode for Claude Desktop"
        echo "  sse   - Run in SSE/HTTP mode on port 8080"
        echo "  http  - Same as sse"
        echo "  dev   - Run in development mode with hot reload"
        exit 1
        ;;
esac