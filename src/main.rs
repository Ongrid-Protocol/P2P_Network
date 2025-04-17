mod bootstrap;
mod regular;
mod node;
mod utils;
mod types;
mod discovery;

use std::error::Error;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use libp2p::Swarm;
use std::num::NonZeroUsize;

// Public exports in mod.rs files
pub mod behavior;
pub mod identity;

// Correct imports in other files
use crate::node::behavior::initialize_swarm;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Setup logging
    let log_file = utils::logging::setup_logging("verification_log.txt")?;
    
    // Load configuration
    let config = utils::config::load_config()?;
    println!("Loaded configuration: {:?}", config.node_type);
    
    // Initialize node identity and network behavior
    let (peer_id, keypair) = node::identity::initialize_identity(&config)?;
    let swarm = node::behavior::initialize_swarm(keypair, &config).await?;
    
    // Create message stores
    let message_store = Arc::new(Mutex::new(HashMap::new()));
    let verification_counter = Arc::new(Mutex::new(0));
    let failed_publish_queue = Arc::new(Mutex::new(VecDeque::new()));
    
    // Run the appropriate node type
    match config.node_type {
        types::NodeType::Bootstrap => {
            println!("Starting as bootstrap node");
            bootstrap::run(
                swarm,
                config,
                message_store,
                verification_counter,
                failed_publish_queue,
                log_file
            ).await?;
        },
        types::NodeType::Regular => {
            println!("Starting as regular node");
            regular::run(
                swarm,
                config,
                message_store,
                verification_counter,
                failed_publish_queue,
                log_file
            ).await?;
        }
    }
    
    config.set_replication_factor(NonZeroUsize::new(3).unwrap());
    
    Ok(())
}
