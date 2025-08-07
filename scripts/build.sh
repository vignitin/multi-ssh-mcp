#!/bin/bash
set -e

# Script to build Multi-SSH MCP Docker image

echo "Building Multi-SSH MCP Server Docker image..."

# Build the image
docker build -t multi-ssh-mcp:latest .

# Tag with version if provided
if [ -n "$1" ]; then
    docker tag multi-ssh-mcp:latest multi-ssh-mcp:$1
    echo "Tagged image as multi-ssh-mcp:$1"
fi

echo "Build complete!"
echo ""
echo "To run in stdio mode (for Claude Desktop):"
echo "  docker-compose --profile stdio run --rm mcp-ssh-stdio"
echo ""
echo "To run in SSE/HTTP mode:"
echo "  docker-compose --profile sse up -d"
echo ""
echo "To run in development mode:"
echo "  docker-compose --profile dev up"