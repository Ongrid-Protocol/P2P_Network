pub mod canister;
pub mod kademlia;
pub mod mdns;

// Re-export canister functions
pub use canister::{connect_to_ic, clear_registry};

// Add bootstrap nodes to Kademlia routing table
pub fn add_bootstrap_nodes(
    kademlia: &mut libp2p::kad::Behaviour<libp2p::kad::store::MemoryStore>,
    bootstrap_nodes: &[String],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for addr_str in bootstrap_nodes {
        if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
            // Extract peer ID from multiaddr if present
            let peer_id = addr
                .iter()
                .find_map(|p| match p {
                    libp2p::multiaddr::Protocol::P2p(hash) => {
                        match libp2p::PeerId::from_bytes(&hash.to_bytes()) {
                            Ok(peer_id) => Some(peer_id),
                            Err(err) => {
                                println!("Failed to convert hash to PeerId: {}", err);
                                None
                            }
                        }
                    },
                    _ => None,
                });
                
            if let Some(peer_id) = peer_id {
                kademlia.add_address(&peer_id, addr.clone());
                println!("Added bootstrap node to Kademlia: {} at {}", peer_id, addr);
            }
        }
    }
    Ok(())
}

// Bootstrap Kademlia DHT
pub fn bootstrap_kademlia(
    kademlia: &mut libp2p::kad::Behaviour<libp2p::kad::store::MemoryStore>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Bootstrapping Kademlia DHT");
    kademlia.bootstrap()?;
    Ok(())
} 