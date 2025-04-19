# Create a directory to store logs
mkdir -p container_logs

# Loop through all nodes and copy their logs
for i in {1..20}; do
  docker cp "node$i:/app/verification_log.txt" "container_logs/node$i-verification_log.txt"
done