#!/bin/sh

# Exit on any error
set -e

# Set default log level if not provided
: "${RUST_LOG:=info}"
export RUST_LOG

# Create log directory if it doesn't exist
mkdir -p "${LOG_DIR:-/app/logs}"

# Start the P2P node
echo "Starting P2P node..."
exec ./p2p 