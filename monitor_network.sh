#!/bin/bash

# This script monitors the status of the P2P network with 100 nodes

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to count running nodes
count_running_nodes() {
  docker ps --format "{{.Names}}" | grep -c "^node[0-9]"
}

# Function to check verification progress
check_verification_progress() {
  local total_verified=0
  local node_count=0
  
  for container in $(docker ps --format "{{.Names}}" | grep "^node[0-9]"); do
    # Get the verification count from logs
    verified=$(docker exec $container grep -c "MSG_VERIFIED" /app/verification_log.txt 2>/dev/null || echo "0")
    
    # If grep fails or returns empty, set to 0
    if [[ -z "$verified" ]]; then
      verified=0
    fi
    
    total_verified=$((total_verified + verified))
    node_count=$((node_count + 1))
  done
  
  echo "${total_verified}:${node_count}"
}

# Function to check connected peers per node
check_peer_connections() {
  local total_connections=0
  local node_count=0
  local max_connections=0
  local min_connections=1000
  
  echo -e "${YELLOW}Sample of node connections:${NC}"
  
  # Get a list of running containers
  containers=$(docker ps --format "{{.Names}}" | grep "^node[0-9]")
  
  # Select 5 random containers for detailed report
  sample_containers=$(echo "$containers" | shuf -n 5)
  
  for container in $containers; do
    # Get the current peer count from logs
    conn_count=$(docker logs $container 2>&1 | grep "Current peer count:" | tail -1 | awk '{print $4}')
    
    # If grep fails or returns empty, set to 0
    if [[ -z "$conn_count" ]]; then
      conn_count=0
    fi
    
    # Update stats
    total_connections=$((total_connections + conn_count))
    node_count=$((node_count + 1))
    
    if [[ $conn_count -gt $max_connections ]]; then
      max_connections=$conn_count
    fi
    
    if [[ $conn_count -lt $min_connections ]]; then
      min_connections=$conn_count
    fi
    
    # Print details for sample nodes
    if [[ "$sample_containers" == *"$container"* ]]; then
      echo -e "  ${BLUE}$container${NC}: $conn_count connected peers"
    fi
  done
  
  # Calculate average
  if [[ $node_count -gt 0 ]]; then
    avg_connections=$((total_connections / node_count))
    echo -e "\n${YELLOW}Connection Statistics:${NC}"
    echo -e "  Min Connections: ${min_connections}"
    echo -e "  Max Connections: ${max_connections}"
    echo -e "  Avg Connections: ${avg_connections}"
  fi
}

# Main monitoring loop
echo -e "${GREEN}Starting P2P Network Monitoring${NC}"
echo -e "${YELLOW}Press Ctrl+C to exit${NC}\n"

while true; do
  clear
  echo -e "${GREEN}=== P2P Network Status ($(date)) ===${NC}\n"
  
  # Node count
  running_nodes=$(count_running_nodes)
  echo -e "${BLUE}Running Nodes:${NC} $running_nodes / 100"
  
  # Verification progress
  verification_data=$(check_verification_progress)
  total_verified=$(echo $verification_data | cut -d':' -f1)
  nodes_with_logs=$(echo $verification_data | cut -d':' -f2)
  
  echo -e "\n${BLUE}Verification Status:${NC}"
  echo -e "  Total Verified Messages: ${total_verified}"
  echo -e "  Nodes with Logs: ${nodes_with_logs} / $running_nodes"
  
  echo -e "\n${BLUE}Network Connectivity:${NC}"
  check_peer_connections
  
  echo -e "\n${YELLOW}Last Updated: $(date)${NC}"
  echo -e "${YELLOW}Refreshing in 10 seconds...${NC}"
  
  sleep 10
done 