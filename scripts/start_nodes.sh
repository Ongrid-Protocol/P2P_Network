#!/bin/bash

# Make sure we're in the right directory
cd "$(dirname "$0")/.."

# Make scripts executable
chmod +x scripts/generate_identities.sh

# Generate identities if they don't exist
if [ ! -d "identities" ]; then
    echo "Generating identities..."
    ./scripts/generate_identities.sh
fi

# Start local dfx if not already running
echo "Starting dfx..."
dfx start --background

# Wait for dfx to be ready
echo "Waiting for dfx to be ready..."
until dfx ping > /dev/null 2>&1; do
    echo "Waiting for dfx..."
    sleep 5
done

# Start the nodes
echo "Starting nodes..."
docker-compose up --build -d

# Wait for nodes to start
echo "Waiting for nodes to start..."
sleep 10

# Show logs
echo "Showing logs..."
docker-compose logs -f 