#!/bin/bash

# Create directory for consolidated logs
LOGS_DIR="consolidated_logs"
mkdir -p $LOGS_DIR

# Get timestamp for the log files
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Function to get logs from a container
get_container_logs() {
  NODE_NUM=$1
  CONTAINER_NAME="node${NODE_NUM}"
  
  # Get Docker logs for verification logs
  if docker ps -a | grep -q $CONTAINER_NAME; then
    echo "Getting logs for $CONTAINER_NAME..."
    
    # Get container verification log file
    docker cp "${CONTAINER_NAME}:/app/verification_log.txt" "${LOGS_DIR}/${CONTAINER_NAME}_verification_${TIMESTAMP}.log" 2>/dev/null
    
    # Get container stdout/stderr logs
    docker logs $CONTAINER_NAME > "${LOGS_DIR}/${CONTAINER_NAME}_stdout_${TIMESTAMP}.log" 2>&1
  else
    echo "Container $CONTAINER_NAME not found, skipping..."
  fi
}

# Get logs for all nodes in parallel (with a limit of 10 parallel processes)
for i in {1..100}; do
  get_container_logs $i &
  
  # Limit to max 10 parallel processes
  if [[ $(jobs -r | wc -l) -ge 10 ]]; then
    wait -n
  fi
done

# Wait for all background processes to finish
wait

echo "All logs have been collected to $LOGS_DIR"

# Create a single compressed archive with all logs
tar -czf "all_logs_${TIMESTAMP}.tar.gz" $LOGS_DIR

echo "Logs compressed to all_logs_${TIMESTAMP}.tar.gz"