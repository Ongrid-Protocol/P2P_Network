# P2P Network Implementation

A decentralized peer-to-peer network implementation with message verification capabilities.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- [OpenSSL](https://www.openssl.org/) (for key generation)
- Internet Computer (IC) local replica running

## Project Structure

```
p2p/
├── src/                    # Source code
├── scripts/                # Utility scripts
├── identities/             # Node configurations
├── Dockerfile             # Docker build configuration
├── docker-compose.yml     # Docker orchestration
├── config.yaml            # Base configuration
└── Cargo.toml            # Rust dependencies
```

## Setup and Deployment

### 1. Start IC Local Replica

```bash
dfx start --clean --background
```

### 2. Generate Node Configurations

```bash
# Make the script executable
chmod +x generate_configs.sh

# Generate configurations for all nodes
./generate_configs.sh
```

This will create individual configuration files for each node in the `identities/` directory.

### 3. Build the Project

```bash
# Build the project
cargo build --release
```

### 4. Deploy with Docker

```bash
# Build and start all containers
docker-compose up --build -d

# View logs for a specific node
docker-compose logs -f node1

# Stop all containers
docker-compose down
```

### 5. Verify Deployment

```bash
# Check running containers
docker-compose ps

# View logs for all nodes
docker-compose logs -f
```

## Node Configuration

Each node's configuration is stored in `identities/nodeX_config.yaml` with the following structure:

```yaml
node:
  name: "nodeX"
  port: <port_number>
  private_key: "<hex_private_key>"
  ic:
    network: "local"
    canister_id: "bkyz2-fmaaa-aaaaa-qaaaq-cai"
    is_local: true
    url: "http://192.168.100.172:49517"
  peer_nodes: []
```

## Message Verification

### 1. Message Signing

Messages are signed using the node's private key. The signature can be verified using the corresponding public key.

### 2. Verification Process

1. Each message includes:
   - The message content
   - The sender's public key
   - The digital signature

2. Verification steps:
   - Extract the public key from the message
   - Verify the signature using the public key
   - Check the message integrity

### 3. Running Verification Tests

```bash
# Run the verification tests
cargo test --test verification
```

## Network Management

### Adding New Nodes

1. Generate a new configuration:
```bash
./generate_configs.sh --nodes 11
```

2. Update `docker-compose.yml` with the new node configuration

3. Restart the network:
```bash
docker-compose up -d
```

### Updating Node Configurations

```bash
# Update configurations for all nodes
./update_node_configs.sh
```

## Troubleshooting

### Common Issues

1. **Node Connection Issues**
   - Check IC replica is running
   - Verify node configurations
   - Check network connectivity

2. **Docker Container Issues**
   - Check container logs: `docker-compose logs -f`
   - Verify volume permissions
   - Check resource limits

3. **Message Verification Failures**
   - Verify key pairs
   - Check message format
   - Validate signature algorithm

### Logging

Logs are available in the following locations:
- Container logs: `docker-compose logs -f`
- Application logs: `/app/logs` in each container
- System logs: `docker logs <container_id>`

## Security Considerations

1. **Key Management**
   - Private keys are stored securely in configuration files
   - Use strong key generation
   - Regular key rotation

2. **Network Security**
   - Use secure communication channels
   - Implement proper access control
   - Monitor network traffic

3. **Message Security**
   - Validate all messages
   - Implement rate limiting
   - Monitor for suspicious activity

## Maintenance

1. **Regular Updates**
   - Update dependencies
   - Apply security patches
   - Rotate keys periodically

2. **Monitoring**
   - Monitor node health
   - Track message verification rates
   - Watch for network anomalies

3. **Backup**
   - Regular configuration backups
   - State persistence
   - Disaster recovery planning

## Support

For issues and support, please:
1. Check the troubleshooting section
2. Review the logs
3. Open an issue in the repository
4. Contact the development team 