use std::collections::{HashSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::io;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

use libp2p::{
    identity, noise, ping, gossipsub, tcp, yamux, Multiaddr, PeerId, swarm::{SwarmEvent, NetworkBehaviour},
    identify, kad,
    mdns,
};
use tokio::time::interval;

use crate::types::{NodeConfig, NodeType, P2pError, SignedMessage};
use crate::utils::{get_public_ip, current_timestamp};
use crate::discovery;

// Message Store types
pub type MessageStore = Arc<Mutex<HashMap<String, SignedMessage>>>;
pub type VerificationCounter = Arc<Mutex<u64>>;
pub type FailedPublishQueue = Arc<Mutex<VecDeque<SignedMessage>>>;

// Network behavior for all nodes
#[derive(NetworkBehaviour)]
pub struct NodeBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub ping: ping::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
}

// Initialize the node's identity
pub fn initialize_identity(config: &NodeConfig) -> Result<(PeerId, identity::Keypair), Box<dyn std::error::Error + Send + Sync>> {
    let private_key_bytes = hex::decode(&config.private_key)?;
    let keypair = identity::Keypair::ed25519_from_bytes(private_key_bytes.clone())?;
    let peer_id = PeerId::from(keypair.public());
    
    println!("Node Type: {:?}", config.node_type);
    println!("Node Name: {}", config.name);
    println!("Peer ID: {}", peer_id);
    
    Ok((peer_id, keypair))
}

// Initialize the swarm with all behaviors
pub async fn initialize_swarm(
    keypair: identity::Keypair,
    config: &NodeConfig,
) -> Result<libp2p::Swarm<NodeBehaviour>, Box<dyn std::error::Error + Send + Sync>> {
    let peer_id = PeerId::from(keypair.public());
    let is_bootstrap = config.node_type == NodeType::Bootstrap;
    
    // Get the public IP for the node
    let public_ip = get_public_ip().await?;
    println!("Using public IP: {}", public_ip);
    
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            // GossipSub configuration
            let message_id_fn = |message: &gossipsub::Message| {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                message.data.hash(&mut hasher);
                gossipsub::MessageId::from(hasher.finish().to_string())
            };
            
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .validation_mode(gossipsub::ValidationMode::Permissive)
                .message_id_fn(message_id_fn)
                .mesh_n_low(2)
                .mesh_n(4)
                .mesh_n_high(8)
                .mesh_outbound_min(1)
                .gossip_lazy(8)
                .history_length(10)
                .history_gossip(5)
                .heartbeat_interval(Duration::from_secs(2))
                .do_px()
                .flood_publish(true)
                .heartbeat_initial_delay(Duration::from_secs(5))
                .build()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;
            
            // Set up mDNS for local discovery
            let mdns = discovery::mdns::configure_mdns(peer_id)?;
            
            // Set up Ping behavior
            let ping = ping::Behaviour::new(ping::Config::new());
            
            // Set up Identify behavior
            let identify = identify::Behaviour::new(identify::Config::new(
                "/p2p/1.0.0".into(),
                key.public(),
            ));
            
            // Set up Kademlia DHT
            let kademlia = discovery::kademlia::configure_kademlia(peer_id, is_bootstrap)?;
            
            Ok(NodeBehaviour {
                gossipsub,
                mdns,
                ping,
                kademlia,
                identify,
            })
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();
    
    Ok(swarm)
} 