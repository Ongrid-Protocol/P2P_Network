#!/bin/bash

# Base port number
BASE_PORT=33335

# Create identities directory if it doesn't exist
mkdir -p identities

# Generate config for each node
for i in {1..20}; do
  PORT=$((BASE_PORT + i - 1))
  # Generate a random private key (32 bytes in hex)
  PRIVATE_KEY=$(openssl rand -hex 32)
  
  cat > "identities/node${i}_config.yaml" << EOL
node:
  name: "node${i}"
  port: ${PORT}
  private_key: "${PRIVATE_KEY}"
  ic:
    network: "local"
    canister_id: "bkyz2-fmaaa-aaaaa-qaaaq-cai"
    is_local: true
    url: "http://127.0.0.1:4943"
  peer_nodes: []
EOL

  echo "Generated config for node${i} with port ${PORT}"
done

# Make the script executable
chmod +x generate_configs.sh 