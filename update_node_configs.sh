#!/bin/bash

# Update all node config files
for i in {1..10}; do
  sed -i '' 's/192.168.1.60/192.168.100.172/g' "identities/node${i}_config.yaml"
  sed -i '' 's/c5kvi-uuaaa-aaaaa-qaaia-cai/bkyz2-fmaaa-aaaaa-qaaaq-cai/g' "identities/node${i}_config.yaml"
  echo "Updated node${i}_config.yaml"
done

echo "All node config files have been updated with the new IP address and canister ID." 