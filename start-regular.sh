#!/bin/bash

# Get the public IP (can be overridden with environment variable)
export PUBLIC_IP=${PUBLIC_IP:-$(curl -s http://checkip.amazonaws.com || echo "127.0.0.1")}
echo "Using public IP: $PUBLIC_IP"

# Make sure the bootstrap nodes are running
if [ "$(docker ps -q -f name=bootstrap-node1)" == "" ]; then
  echo "Bootstrap nodes are not running. Start them first with ./start-bootstrap.sh"
  exit 1
fi

# Start the regular nodes
docker-compose -f docker-compose.regular.yml up -d

echo "Regular nodes started. Check logs with:"
echo "docker-compose -f docker-compose.regular.yml logs -f" 