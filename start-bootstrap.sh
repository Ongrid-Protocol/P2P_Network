#!/bin/bash

# Get the public IP (can be overridden with environment variable)
export PUBLIC_IP=${PUBLIC_IP:-$(curl -s http://checkip.amazonaws.com || echo "127.0.0.1")}
echo "Using public IP: $PUBLIC_IP"

# Create network if it doesn't exist
docker network create p2p-network 2>/dev/null || true

# Start the bootstrap nodes
docker-compose -f docker-compose.bootstrap.yml up -d

echo "Bootstrap nodes started. Check logs with:"
echo "docker-compose -f docker-compose.bootstrap.yml logs -f" 