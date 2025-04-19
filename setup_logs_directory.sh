#!/bin/bash

# Create log directories for all 100 nodes
for i in {1..100}; do
  mkdir -p logs/node${i}
  touch logs/node${i}/verification_log.txt
  echo "Created log directory for node${i}"
done

echo "All log directories created successfully." 