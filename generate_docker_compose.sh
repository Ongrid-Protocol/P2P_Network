#!/bin/bash

# This script generates a docker-compose.yml file with 100 node services

# Base configuration
cat > docker-compose.yml << EOL
# Common build definition using YAML anchors
x-node-build: &node-build
  build:
    context: .
    dockerfile: Dockerfile

services:
EOL

# Add nodes from 1 to 100
for i in {1..100}; do
  MDNS_PORT=$((5353 + i))
  
  cat >> docker-compose.yml << EOL
  node${i}:
    <<: *node-build
    image: p2p-node-image
    volumes:
      - ./identities/node${i}_config.yaml:/app/config.yaml:ro
      - ./logs/node${i}:/app/logs
      - ./logs/node${i}/verification_log.txt:/app/verification_log.txt
    environment:
      - NODE_NAME=node${i}
      - RUST_LOG=info
      - MDNS_PORT=${MDNS_PORT}
    network_mode: host
    command: sh -c "sleep $((i * 2 % 10 + 5)) && /app/p2p"
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 500M

EOL
done

# Add IC canister
cat >> docker-compose.yml << EOL
  # Add the Internet Computer canister service for node registry
  ic-canister:
    image: dfinity/ic-standalone:latest
    ports:
      - "4943:4943"
    volumes:
      - ic_state:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:4943/api/v2/status"]
      interval: 10s
      timeout: 5s
      retries: 3

volumes:
  ic_state:
EOL

echo "Generated docker-compose.yml with 100 nodes" 