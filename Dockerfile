# Stage 1: Build environment
FROM rust:latest AS builder

# Install build dependencies (separate layer for better caching)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    libssl-dev \
    pkg-config

# Create non-root user for building
RUN useradd -m -u 1001 rust
WORKDIR /app
RUN chown rust:rust /app

# Switch to non-root user
USER rust

# Create cargo directory and set ownership
RUN mkdir -p /home/rust/.cargo && \
    chown -R rust:rust /home/rust/.cargo

# Copy dependency files with explicit ownership
COPY --chown=rust:rust Cargo.toml Cargo.lock ./

# Debug: Show contents of Cargo.toml
RUN cat Cargo.toml

# Create dummy src for dependency caching
RUN mkdir -p src && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs

# First build - show output directly
RUN RUST_LOG=debug \
    RUST_BACKTRACE=full \
    cargo build --release -vv

# Clean up dummy build
RUN rm -f target/release/deps/p2p*

# Copy the entire src directory and config
COPY --chown=rust:rust src ./src/
COPY --chown=rust:rust identities ./identities/

# Debug: List contents to verify files
RUN ls -la && \
    ls -la src/ && \
    cat src/main.rs | head -n 5

# Final build with full output
RUN RUST_LOG=debug \
    RUST_BACKTRACE=full \
    cargo build --release -vv || (find . -type f -name "*.rs" -exec cat {} \;)

# Stage 2: Runtime environment
FROM rust:latest

# Create non-root user for running
RUN useradd -m -u 1001 app

# Install runtime dependencies and logging tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    ca-certificates

WORKDIR /app

# Create necessary directories
RUN mkdir -p /app/data /app/logs && \
    chown -R app:app /app

# Setup log rotation
COPY --chown=root:root <<EOF /etc/logrotate.d/p2p
/app/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 app app
}
EOF

# Copy built binary and config
COPY --from=builder /app/target/release/p2p .
COPY --from=builder /app/identities ./identities/

# Set proper permissions
RUN chown -R app:app /app && \
    chmod -R 755 /app && \
    ls -la /app

# Switch to non-root user
USER app

# Environment variables
ENV RUST_LOG=debug
ENV RUST_BACKTRACE=full

# Start the application with logging
CMD cp identities/${NODE_NAME}_config.yaml config.yaml && \
    ls -la && \
    pwd && \
    exec ./p2p