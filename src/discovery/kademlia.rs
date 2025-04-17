use libp2p::{
    kad::{self, store::MemoryStore, Mode},
    PeerId,
};
use std::error::Error;

// Configure Kademlia DHT with the appropriate mode based on node type
pub fn configure_kademlia(
    peer_id: PeerId,
    is_bootstrap: bool,
) -> Result<kad::Behaviour<MemoryStore>, Box<dyn Error + Send + Sync>> {
    // Create a Kademlia store for this local peer
    let store = MemoryStore::new(peer_id);
    
    // Create a Kademlia behavior with options
    let mut config = kad::Config::default();
    
    // Set replication and TTL values suitable for our use case
    config.set_replication_factor(3);
    config.set_record_ttl(Some(std::time::Duration::from_secs(3600 * 24))); // 24 hours
    config.set_query_timeout(std::time::Duration::from_secs(60));
    
    let mut kademlia = kad::Behaviour::with_config(peer_id, store, config);
    
    // Set the mode based on the node type
    if is_bootstrap {
        kademlia.set_mode(Some(Mode::Server));
        println!("Kademlia configured in server mode");
    } else {
        kademlia.set_mode(Some(Mode::Client));
        println!("Kademlia configured in client mode");
    }
    
    Ok(kademlia)
}

// Start bootstrapping process for Kademlia
pub fn bootstrap_kademlia(
    kademlia: &mut kad::Behaviour<MemoryStore>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Bootstrapping Kademlia DHT");
    kademlia.bootstrap()?;
    Ok(())
} 