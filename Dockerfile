# Build stage
FROM python:3.10-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Add uvicorn for SSE support
RUN pip install --no-cache-dir uvicorn[standard]

# Runtime stage
FROM python:3.10-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash mcp

# Set working directory
WORKDIR /app

# Copy application files
COPY --chown=mcp:mcp multi_ssh_mcp.py security_utils.py ./

# Create directories for SSH and config
RUN mkdir -p /home/mcp/.ssh /config && \
    chown -R mcp:mcp /home/mcp/.ssh /config && \
    chmod 700 /home/mcp/.ssh

# Switch to non-root user
USER mcp

# Environment variables
ENV MCP_TRANSPORT=stdio \
    MCP_CONFIG_PATH=/config/servers.json \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8080 \
    PYTHONUNBUFFERED=1

# Volume for configuration and SSH keys
VOLUME ["/config", "/home/mcp/.ssh"]

# Expose port for SSE mode
EXPOSE 8080

# Health check for container monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; s = socket.socket(); s.connect(('localhost', 8080))" || exit 1

# Default command
ENTRYPOINT ["python", "multi_ssh_mcp.py"]
CMD ["/config/servers.json"]