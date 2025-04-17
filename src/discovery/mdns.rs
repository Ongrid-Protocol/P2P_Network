use libp2p::{
    mdns,
    PeerId,
};
use std::error::Error;

// Configure mDNS for local network peer discovery
pub fn configure_mdns(
    peer_id: PeerId,
) -> Result<mdns::tokio::Behaviour, Box<dyn Error + Send + Sync>> {
    // Create new mDNS behavior with default configuration
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;
    println!("mDNS configured for local discovery");
    Ok(mdns)
} 