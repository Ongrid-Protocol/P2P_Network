use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use candid::Principal;
use futures::prelude::*;
use libp2p::{
    PeerId, Multiaddr, multiaddr::Protocol, 
    swarm::{SwarmEvent, NetworkBehaviour},
    gossipsub, identify, kad,
};
use tokio::time::interval;

use crate::types::{NodeConfig, NodeType, SignedMessage};
use crate::node::{NodeBehaviour, MessageStore, VerificationCounter, FailedPublishQueue};
use crate::utils::{self, get_public_ip, write_log, current_timestamp};
use crate::discovery::{self, add_bootstrap_nodes, bootstrap_kademlia};

// Run a regular node
pub async fn run(
    mut swarm: libp2p::Swarm<NodeBehaviour>,
    config: NodeConfig,
    message_store: MessageStore,
    verification_counter: VerificationCounter,
    failed_publish_queue: FailedPublishQueue,
    log_file: utils::logging::LogFile,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Connect to IC canister to get bootstrap nodes
    let agent = discovery::canister::connect_to_ic(&config.ic)?;
    let canister_id = Principal::from_text(&config.ic.canister_id)?;
    
    // Get the public IP for the node
    let public_ip = get_public_ip().await?;
    let peer_id = *swarm.local_peer_id();
    
    // Fetch bootstrap nodes from the IC canister
    let mut bootstrap_nodes = discovery::canister::fetch_bootstrap_nodes(&agent, &canister_id).await?;
    
    // Also use any bootstrap nodes from config
    if !config.bootstrap_nodes.is_empty() {
        bootstrap_nodes.extend(config.bootstrap_nodes.clone());
    }
    
    // Create GossipSub topic
    let topic = gossipsub::IdentTopic::new("p2p-network-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    println!("Subscribed to topic: {}", topic.hash());
    
    // Create listen address using public IP
    let listen_addr = format!("/ip4/{}/tcp/{}", public_ip, config.port).parse()?;
    swarm.listen_on(listen_addr)?;
    
    // Add bootstrap nodes to Kademlia and try to connect
    add_bootstrap_nodes(&mut swarm.behaviour_mut().kademlia, &bootstrap_nodes)?;
    
    // Try connecting to bootstrap nodes
    let mut bootstrap_connected = false;
    for addr_str in &bootstrap_nodes {
        if let Ok(addr) = addr_str.parse::<Multiaddr>() {
            match swarm.dial(addr.clone()) {
                Ok(_) => {
                    println!("Dialing bootstrap node: {}", addr);
                    bootstrap_connected = true;
                }
                Err(e) => println!("Failed to dial bootstrap node {}: {}", addr, e),
            }
        }
    }
    
    // If no bootstrap nodes available, rely on local discovery
    if !bootstrap_connected {
        println!("No bootstrap nodes available, relying on mDNS discovery");
    }
    
    // Set up intervals
    let mut kad_bootstrap_interval = interval(Duration::from_secs(300));
    let mut retry_publish_interval = interval(Duration::from_secs(30));
    let mut metrics_interval = interval(Duration::from_secs(60));
    
    // Message processing variables
    let local_peer_id = peer_id;
    let log_file_clone = log_file.clone();
    let message_store_clone = message_store.clone();
    let verification_counter_clone = verification_counter.clone();
    let failed_publish_queue_clone = failed_publish_queue.clone();
    
    // Manage connections
    let mut last_mesh_attempt = Instant::now();
    let mut mesh_attempt_backoff = Duration::from_secs(5);
    let max_backoff = Duration::from_secs(60);
    
    // Metrics
    let network_metrics = Arc::new(Mutex::new(crate::types::NetworkMetrics::default()));
    let metrics_clone = network_metrics.clone();
    
    println!("Regular node initialized. Waiting for peers and network events.");
    
    // Try initial Kademlia bootstrap if we have bootstrap nodes
    if bootstrap_connected {
        if let Err(e) = bootstrap_kademlia(&mut swarm.behaviour_mut().kademlia) {
            println!("Initial Kademlia bootstrap error: {:?}", e);
        }
    }
    
    // Main event loop
    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    event, 
                    &topic, 
                    &mut swarm, 
                    &message_store_clone, 
                    &verification_counter_clone, 
                    &failed_publish_queue_clone,
                    &log_file_clone,
                    &metrics_clone,
                    local_peer_id
                ).await?;
            }
            _ = kad_bootstrap_interval.tick() => {
                println!("Performing periodic Kademlia bootstrap");
                if let Err(e) = bootstrap_kademlia(&mut swarm.behaviour_mut().kademlia) {
                    println!("Failed to bootstrap Kademlia: {:?}", e);
                }
                
                // Look up random peer to keep routing table fresh
                let random_peer_id = PeerId::random();
                swarm.behaviour_mut().kademlia.get_closest_peers(random_peer_id);
            }
            _ = retry_publish_interval.tick() => {
                retry_failed_messages(&mut swarm, &topic, &failed_publish_queue_clone).await;
            }
            _ = metrics_interval.tick() => {
                log_network_metrics(&swarm, &topic, &metrics_clone);
            }
        }
        
        // Mesh formation check with backoff
        let now = Instant::now();
        if now.duration_since(last_mesh_attempt) > mesh_attempt_backoff {
            check_mesh_formation(&mut swarm, &topic, &mut last_mesh_attempt, &mut mesh_attempt_backoff, max_backoff).await?;
        }
    }
}

// Helper to handle swarm events
async fn handle_swarm_event(
    event: SwarmEvent<<NodeBehaviour as libp2p::swarm::NetworkBehaviour>::ToSwarm>,
    topic: &gossipsub::IdentTopic,
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    _message_store: &MessageStore,
    _verification_counter: &VerificationCounter,
    _failed_publish_queue: &FailedPublishQueue,
    _log_file: &utils::logging::LogFile,
    metrics: &Arc<Mutex<crate::types::NetworkMetrics>>,
    local_peer_id: PeerId,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            println!("Regular node listening on: {}", address);
        }
        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
            println!("Connection established with peer: {}", peer_id);
            
            // Add to routing table
            let addr = endpoint.get_remote_address().clone();
            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
            
            // Subscription exchange protocol
            let topics: Vec<_> = swarm.behaviour().gossipsub.topics().map(|t| t.to_string()).collect();
            for topic_str in topics {
                println!("Telling peer {} about our subscription to {}", peer_id, topic_str);
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
            }
            
            // Send hello message to trigger protocol
            let hello_msg = format!("HELLO_PROTOCOL {} {}", local_peer_id, current_timestamp());
            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), hello_msg.as_bytes()) {
                println!("Failed to publish hello message: {}", e);
            }
            
            // Update metrics
            let mut metrics_guard = metrics.lock().unwrap();
            metrics_guard.successful_connections += 1;
            metrics_guard.connection_attempts += 1;
        }
        
        // Handle other events...
        _ => {}
    }
    
    Ok(())
}

// Helper to retry failed message publications
async fn retry_failed_messages(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    topic: &gossipsub::IdentTopic,
    failed_publish_queue: &FailedPublishQueue,
) {
    let mut queue = failed_publish_queue.lock().unwrap();
    if !queue.is_empty() {
        println!("Retrying publication for {} queued messages.", queue.len());
        let mut still_failed = VecDeque::new();
        
        while let Some(message_to_retry) = queue.pop_front() {
            match serde_json::to_string(&message_to_retry) {
                Ok(json_message) => {
                    if let Err(e) = swarm
                        .behaviour_mut().gossipsub
                        .publish(topic.clone(), json_message.as_bytes())
                    {
                        println!("Retry publish error: {e:?}. Re-queuing.");
                        still_failed.push_back(message_to_retry);
                    } else {
                        println!("Retry publish successful for hash {}.", message_to_retry.message_hash);
                    }
                }
                Err(e) => {
                    println!("Retry serialization error: {}. Re-queuing.", e);
                    still_failed.push_back(message_to_retry);
                }
            }
        }
        
        queue.extend(still_failed);
    }
}

// Helper to log network metrics
fn log_network_metrics(
    swarm: &libp2p::Swarm<NodeBehaviour>,
    topic: &gossipsub::IdentTopic,
    metrics: &Arc<Mutex<crate::types::NetworkMetrics>>,
) {
    let metrics_guard = metrics.lock().unwrap();
    let mesh_peers = swarm.behaviour().gossipsub.mesh_peers(&topic.hash()).count();
    let connected_peers = swarm.connected_peers().count();
    
    println!("\n=== Regular Node Network Metrics ===");
    println!("Connection Success Rate: {:.2}%", 
        if metrics_guard.connection_attempts > 0 {
            (metrics_guard.successful_connections as f64 / metrics_guard.connection_attempts as f64) * 100.0
        } else {
            0.0
        });
    println!("Current Mesh Size: {}", mesh_peers);
    println!("Connected Peers: {}", connected_peers);
    println!("=====================\n");
}

// Helper to check and improve mesh formation
async fn check_mesh_formation(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    topic: &gossipsub::IdentTopic,
    last_mesh_attempt: &mut Instant,
    mesh_attempt_backoff: &mut Duration,
    max_backoff: Duration,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let peer_ids: Vec<PeerId> = swarm.connected_peers().cloned().collect();
    let mesh_peers: HashSet<PeerId> = swarm.behaviour().gossipsub.mesh_peers(&topic.hash()).cloned().collect();
    
    if mesh_peers.len() < 4 && !peer_ids.is_empty() {
        println!("Mesh size below target ({}/4), attempting to improve mesh formation", mesh_peers.len());
        
        // Broadcast a GROUP message
        let timestamp = current_timestamp();
        let group_message = format!("GROUP_MESH_ATTEMPT {} {}", swarm.local_peer_id(), timestamp);
        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), group_message.as_bytes()) {
            println!("Failed to publish group mesh message: {}", e);
        }
        
        // Only for critical low size, try additional measures
        if mesh_peers.len() < 2 {
            println!("Critical low mesh size ({}), performing emergency bootstrap", mesh_peers.len());
            if let Err(e) = bootstrap_kademlia(&mut swarm.behaviour_mut().kademlia) {
                println!("Emergency bootstrap failed: {:?}", e);
            }
            
            // Try direct peering with each peer
            for peer_id in peer_ids.iter().take(3) {
                if !mesh_peers.contains(peer_id) {
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(peer_id);
                    
                    // Direct ping message
                    let ping_message = format!("DIRECT_PING {} {}", swarm.local_peer_id(), timestamp);
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), ping_message.as_bytes()) {
                        println!("Failed to publish direct ping: {}", e);
                    }
                }
            }
            
            // Exponential backoff for emergency
            *mesh_attempt_backoff = std::cmp::min(*mesh_attempt_backoff * 2, max_backoff);
        } else {
            // Linear backoff for normal situations
            *mesh_attempt_backoff = std::cmp::min(*mesh_attempt_backoff + Duration::from_secs(1), max_backoff);
        }
        *last_mesh_attempt = Instant::now();
    } else if mesh_peers.len() >= 4 {
        // Reset backoff when things are good
        *mesh_attempt_backoff = Duration::from_secs(5);
    }
    
    Ok(())
} 