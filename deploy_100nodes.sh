#!/bin/bash

# Master script to set up and deploy a 100-node cluster

# Function to check if a command exists
check_command() {
  if ! command -v $1 &> /dev/null; then
    echo "Error: $1 is required but not installed."
    exit 1
  fi
}

# Check required commands
check_command docker
check_command docker-compose

# Step 1: Generate node configurations
echo "=== Step 1: Generating configurations for 100 nodes ==="
chmod +x generate_configs.sh
./generate_configs.sh
echo "Configuration generation complete!"

# Step 2: Set up log directories
echo "=== Step 2: Setting up log directories ==="
chmod +x setup_logs_directory.sh
./setup_logs_directory.sh
echo "Log directories setup complete!"

# Step 3: Generate the docker-compose.yml file
echo "=== Step 3: Generating docker-compose.yml ==="
chmod +x generate_docker_compose.sh
./generate_docker_compose.sh
echo "Docker Compose file generation complete!"

# Step 4: Build the Docker image
echo "=== Step 4: Building Docker image ==="
docker-compose build
echo "Docker image build complete!"

# Step 5: Start the containers in groups to prevent resource exhaustion
echo "=== Step 5: Starting containers in groups ==="

# Function to start a group of nodes
start_node_group() {
  local start=$1
  local end=$2
  local services=""
  
  for i in $(seq $start $end); do
    services="$services node$i"
  done
  
  echo "Starting nodes $start to $end..."
  docker-compose up -d $services
  echo "Nodes $start to $end started!"
}

# Start the IC canister first
echo "Starting IC canister..."
docker-compose up -d ic-canister
echo "Waiting for IC canister to initialize..."
sleep 10

# Start nodes in groups of 10
for group in $(seq 0 9); do
  start=$((group * 10 + 1))
  end=$((start + 9))
  start_node_group $start $end
  echo "Waiting 30 seconds before starting the next group..."
  sleep 30
done

echo "=== All 100 nodes started! ==="
echo "To view logs, use ./get_logs.sh"
echo "To stop all nodes: docker-compose down"
echo "To view running nodes: docker-compose ps" 