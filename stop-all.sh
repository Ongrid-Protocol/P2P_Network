#!/bin/bash

# Stop regular nodes first
echo "Stopping regular nodes..."
docker-compose -f docker-compose.regular.yml down

# Then stop bootstrap nodes
echo "Stopping bootstrap nodes..."
docker-compose -f docker-compose.bootstrap.yml down

echo "All nodes stopped." 