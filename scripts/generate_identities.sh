#!/bin/bash

# Create directory for identities if it doesn't exist
mkdir -p identities

# Use the existing canister ID
CANISTER_ID="bkyz2-fmaaa-aaaaa-qaaaq-cai"
echo "Using existing canister ID: $CANISTER_ID"

# Generate 10 identities
for i in {1..10}; do
    # Generate a random private key
    private_key=$(openssl rand -hex 32)
    
    # Create config file for this node
    cat > "identities/node${i}_config.yaml" << EOF
node:
  name: "node${i}"
  port: $((33335 + i))
  private_key: "${private_key}"
  ic:
    network: "local"
    canister_id: "${CANISTER_ID}"
    is_local: true
    url: "http://192.168.100.172:49517"  # Using local network IP
  peer_nodes: []
EOF

    echo "Generated identity for node${i}"
done

echo "All identities generated in the identities directory" 