use std::{error::Error, hash::{Hash, Hasher},collections::hash_map::DefaultHasher, collections::HashSet, fs::{File, OpenOptions}, path::Path, io::{Read, Write}};
use serde::{Deserialize, Serialize};
use futures::prelude::*;
use libp2p::{identity, noise, ping, gossipsub,mdns,swarm::{SwarmEvent,NetworkBehaviour}, tcp, yamux, Multiaddr, PeerId};
use tracing_subscriber::EnvFilter;
use ic_agent::{Agent};
use candid::{CandidType, Principal, Deserialize as CandidDeserialize};
use tokio::time::{interval, Duration};
use tokio::io::{self, AsyncBufReadExt};
use std::net::Ipv4Addr;
use libp2p::multiaddr::Protocol;
use std::env;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use sha2::{Sha256, Digest};
use hex;
use serde_json;
use std::time::{SystemTime, UNIX_EPOCH};

// Define the structure for signed messages
#[derive(Debug, Serialize, Deserialize, Clone)]
struct SignedMessage {
    content: String,
    originator_id: String, // PeerId as string
    message_hash: String, // SHA256 hash of content
    signatures: HashSet<String>, // Set of PeerIds (as strings) that have signed
}

#[derive(Debug, Serialize, Deserialize)]
struct NodeConfig {
    node: NodeSettings,
}

#[derive(Debug, Serialize, Deserialize)]
struct NodeSettings {
    name: String,
    port: u16,
    private_key: String,
    ic: ICSettings,
    peer_nodes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ICSettings {
    network: String,
    canister_id: String,
    is_local: bool,
    url: String,
}

#[derive(CandidType, CandidDeserialize, Debug)]
struct Node {
    name: String,
    principal: Principal,
    multiaddress: String,
    last_heartbeat: u64,
}

#[derive(CandidType, CandidDeserialize, Debug)]
struct RegisterResponse {
    success: bool,
    principal: Principal,
}

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
}

// Define shared state type
type MessageStore = Arc<Mutex<HashMap<String, SignedMessage>>>;

async fn register_node(agent: &Agent, canister_id: &Principal, node_principal: Principal, name: &str, multiaddr: &str) -> Result<RegisterResponse, Box<dyn Error>> {
    let response = agent
        .update(canister_id, "register_node")
        .with_arg(candid::encode_args((
            name,
            multiaddr,
            node_principal,
        ))?)
        .call_and_wait()
        .await?;

    let result: RegisterResponse = candid::decode_one(&response)?;
    Ok(result)
}

async fn send_heartbeat(agent: &Agent, canister_id: &Principal, node_principal: Principal, name: &str, multiaddr: &str) -> Result<bool, Box<dyn Error>> {
    let response = agent
        .update(canister_id, "heartbeat")
        .with_arg(candid::encode_args((
            node_principal,
            name,
            multiaddr,
        ))?)
        .call_and_wait()
        .await?;

    let result: bool = candid::decode_one(&response)?;
    Ok(result)
}

async fn fetch_peer_nodes(agent: &Agent, config: &NodeSettings) -> Result<Vec<String>, Box<dyn Error>> {
    let canister_id = Principal::from_text(&config.ic.canister_id)?;
    let response = agent
        .query(&canister_id, "get_nodes")
        .with_arg(candid::encode_args(()).unwrap())
        .call()
        .await?;

    let nodes: Vec<Node> = candid::decode_one(&response)?;
    println!("Fetched nodes from canister: {:?}", nodes);
    
    Ok(nodes.into_iter()
        .map(|node| node.multiaddress)
        .collect())
}

fn load_config() -> Result<NodeConfig, Box<dyn Error>> {
    let config_path = Path::new("config.yaml");
    let file = File::open(config_path)?;
    let config: NodeConfig = serde_yaml::from_reader(file)?;
    Ok(config)
}

fn save_principal_id(principal: &Principal) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("node_principal.txt")?;
    
    file.write_all(principal.to_string().as_bytes())?;
    Ok(())
}

fn load_principal_id() -> Result<Option<Principal>, Box<dyn Error>> {
    let path = Path::new("node_principal.txt");
    if !path.exists() {
        return Ok(None);
    }

    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    
    if contents.is_empty() {
        return Ok(None);
    }

    let principal = Principal::from_text(contents.trim())?;
    Ok(Some(principal))
}

fn sign_message(message: &[u8], keypair: &identity::Keypair) -> Vec<u8> {
    keypair.sign(message).expect("Failed to sign message")
}

fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, Box<dyn Error>> {
    let mut key_bytes = public_key.to_vec();
    let keypair = identity::Keypair::ed25519_from_bytes(&mut key_bytes)?;
    let public_key = keypair.public();
    Ok(public_key.verify(message, signature))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    // Load configuration
    let config = load_config()?;
    println!("Loaded configuration: {:?}", config);

    // Create libp2p identity from private key
    let private_key_bytes = hex::decode(&config.node.private_key)?;
    let id_keys = identity::Keypair::ed25519_from_bytes(private_key_bytes.clone())?;
    let peer_id = PeerId::from(id_keys.public());
    println!("Peer ID: {}", peer_id);

    // Generate Principal ID from the node's private key bytes
    let node_principal = Principal::self_authenticating(&private_key_bytes);
    println!("Node Principal ID: {}", node_principal);

    // Initialize the shared message store
    let message_store: MessageStore = Arc::new(Mutex::new(HashMap::new()));

    // Read IC URL from environment variable, fall back to config if not set (optional fallback)
    let ic_url = env::var("IC_URL").unwrap_or_else(|_| {
        println!("Warning: IC_URL environment variable not set, using URL from config.yaml");
        config.node.ic.url.clone()
    });
    println!("Using IC URL: {}", ic_url);

    // Create IC agent with proper configuration
    let agent = Agent::builder()
        .with_url(&ic_url)
        .build()?;

    // Always fetch root key for local development
    if config.node.ic.is_local {
        agent.fetch_root_key().await?;
    }

    // Get the canister ID from config
    let canister_id = Principal::from_text(&config.node.ic.canister_id)?;
    println!("Canister ID: {}", canister_id);

    // Construct the multiaddress using 127.0.0.1 and the configured port for local setup
    let local_multiaddr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", config.node.port, peer_id);
    println!("Using local multiaddress for registration/heartbeat: {}", local_multiaddr);

    // Attempt initial registration using the local multiaddr
    match register_node(
        &agent,
        &canister_id,
        node_principal,
        &config.node.name,
        &local_multiaddr, // Use local_multiaddr here
    ).await {
        Ok(response) => {
            if response.success {
                println!("Successfully registered node with canister");
                println!("Assigned Principal ID: {}", response.principal);
                if let Err(e) = save_principal_id(&response.principal) {
                    println!("Failed to save principal ID: {}", e);
                }
            } else {
                println!("Failed to register node with canister");
            }
        }
        Err(e) => println!("Error registering node: {}", e),
    }

    // Fetch active peer nodes from the canister
    let fetched_nodes = fetch_peer_nodes(&agent, &config.node).await?;
    println!("Fetched Peer Nodes from canister: {:?}", fetched_nodes);

    // Filter out own address before further processing
    let active_nodes: Vec<String> = fetched_nodes
        .into_iter()
        .filter(|addr_str| {
            if let Ok(ma) = addr_str.parse::<Multiaddr>() {
                if let Some(Protocol::P2p(fetched_peer_id)) = ma.iter().last() {
                    // Keep the address if the fetched peer ID is different from our own
                    if fetched_peer_id != peer_id { // Compare with own peer_id
                        return true;
                    }
                }
            }
            // Discard if parsing failed, no peer ID found, or if it's our own ID
            println!("Discarding own address or invalid address: {}", addr_str);
            false
        })
        .collect();

    println!("Filtered Peer Nodes (excluding self): {:?}", active_nodes);

    // Transform the filtered addresses to use localhost if they are external IPs
    let dialable_node_addrs: Vec<String> = active_nodes.iter().map(|addr_str| { // Use the filtered active_nodes list
        if let Ok(ma) = addr_str.parse::<Multiaddr>() {
            let components: Vec<_> = ma.iter().collect();
            // Check if the first component is /ip4/ and it's not loopback/private
            if let Some(Protocol::Ip4(ip)) = components.get(0) {
                if !ip.is_loopback() && !ip.is_private() {
                    // Rebuild the address with 127.0.0.1
                    let mut new_ma = Multiaddr::empty();
                    new_ma.push(Protocol::Ip4(Ipv4Addr::LOCALHOST));
                    // Append the rest of the components (e.g., /tcp/port/p2p/peerid)
                    for component in components.iter().skip(1) {
                        new_ma.push(component.clone());
                    }
                    println!("Transformed remote address {} to {}", addr_str, new_ma);
                    return new_ma.to_string();
                }
            }
        }
        // If parsing failed or no transformation needed, return original
        addr_str.clone()
    }).collect();

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            // To content-address message, we can take the hash of message and use it as an ID.
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            // Set a custom gossipsub configuration
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
                .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message
                // signing)
                .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
                // Explicitly set low mesh thresholds for small networks
                .mesh_n_low(1)
                .mesh_n(2)
                .mesh_n_high(3)
                // Ensure mesh_outbound_min <= mesh_n_low
                .mesh_outbound_min(1)
                .build()
                .map_err(io::Error::other)?; // Use std::io::Error here

            // build a gossipsub network behaviour
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;

            // Configure Ping
            let ping = ping::Behaviour::new(ping::Config::new());

            Ok(MyBehaviour { gossipsub, mdns, ping })
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();

    // create a Gossipsub topic
    let topic = gossipsub::IdentTopic::new("testing");
    // subscribes to our topic
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    // Use configured port
    let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", config.node.port).parse()?;
    swarm.listen_on(listen_addr)?;

    // Connect to active nodes using potentially transformed addresses
    let mut target_peers = HashSet::new(); // Store PeerIds from active_nodes
    for addr in &dialable_node_addrs { // Use the transformed list
        if let Ok(remote_addr) = addr.parse::<Multiaddr>() {
            if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = remote_addr.iter().last() {
                target_peers.insert(peer_id);
                match swarm.dial(remote_addr.clone()) {
                    Ok(_) => {
                        println!("Dialing active node: {}", addr); // Log the address being dialed
                    }
                    Err(e) => println!("Failed to dial {}: {}", addr, e),
                }
            } else {
                println!("Could not extract PeerId from Multiaddr: {}", addr);
            }
        } else {
            println!("Failed to parse Multiaddr: {}", addr);
        }
    }

    let mut heartbeat_interval = interval(Duration::from_secs(30));
    let mut signing_request_interval = interval(Duration::from_secs(10));

    println!("Node initialized. Waiting for peers and network events.");

    // --- Clone necessary variables for the loop --- 
    let message_store_clone = message_store.clone();
    let local_peer_id = peer_id; // Clone peer_id for use in the loop
    let keypair_clone = id_keys; // Clone keypair if needed for future actual verification

    // Main event loop
    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("\nNode Information:");
                        println!("Name: {}", config.node.name);
                        println!("PeerId: {}", peer_id);
                        println!("Local Multiaddr: {}/p2p/{}", address, peer_id);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        println!("Connection established with peer: {}", peer_id);
                        println!("Connected via: {}", endpoint.get_remote_address());
                        // If this is one of the peers from the canister list, add it to gossipsub
                        if target_peers.contains(&peer_id) {
                            println!("Adding pre-configured peer {} to gossipsub explicit peers", peer_id);
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            println!("Added peer {} to gossipsub explicit peers", peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, _multiaddr) in list {
                            println!("mDNS discovered a new peer: {peer_id}");
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                        for (peer_id, _multiaddr) in list {
                            println!("mDNS discover peer has expired: {peer_id}");
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message_id: _id,
                        message,
                    })) => {
                        // Attempt to deserialize as SignedMessage JSON
                        if let Ok(received_message) = serde_json::from_slice::<SignedMessage>(&message.data) {
                            println!("Received SignedMessage: Hash {} from Peer {}", received_message.message_hash, propagation_source);

                            let mut store = message_store_clone.lock().unwrap();
                            let message_hash = received_message.message_hash.clone();
                            
                            // Get the entry or insert a new one if we haven't seen this message hash
                            let entry = store.entry(message_hash.clone()).or_insert_with(|| {
                                println!("Adding new message entry for hash: {}", message_hash);
                                received_message.clone() // If new, store the received version
                            });

                            // Add the sender's signature (PeerId)
                            let mut needs_republish = false;
                            let sender_peer_id_str = propagation_source.to_string();

                            // Merge signatures from received message into our stored version
                            for sig_peer_id in received_message.signatures {
                                if entry.signatures.insert(sig_peer_id) {
                                    // If we added a new signature, mark for potential republish
                                    needs_republish = true; 
                                }
                            }
                            
                            // Add sender's signature if not already present (ensures sender is counted)
                            if entry.signatures.insert(sender_peer_id_str) {
                                needs_republish = true; 
                            }

                            let current_sig_count = entry.signatures.len();
                            println!("Signature count for hash {}: {}", message_hash, current_sig_count);

                            // Check for verification threshold
                            if current_sig_count == 3 {
                                println!("*** MESSAGE VERIFIED ({} signatures): Hash {} ***", current_sig_count, message_hash);
                                // Could add logic here to stop re-publishing verified messages
                                needs_republish = false; // Example: Don't republish verified messages
                            }

                            // If we added a new signature and haven't reached verification, republish
                            if needs_republish {
                                println!("Republishing message with updated signatures: Hash {}", message_hash);
                                match serde_json::to_string(&*entry) { // Republish updated entry
                                    Ok(json_message) => {
                                        if let Err(e) = swarm
                                            .behaviour_mut().gossipsub
                                            .publish(topic.clone(), json_message.as_bytes())
                                        {
                                            println!("Republish error: {e:?}");
                                        }
                                    }
                                    Err(e) => {
                                        println!("Error serializing message for republish: {}", e);
                                    }
                                }
                            }
                        } else {
                            // Handle as plain text message
                            println!(
                                "Got plain text message: '{}' from peer: {}",
                                String::from_utf8_lossy(&message.data),
                                propagation_source
                            );
                        }
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Ping(event)) => {
                        println!("Ping event: {:?}", event);
                    },
                    SwarmEvent::Dialing { peer_id, connection_id } => {
                        println!("Dialing peer: {:?} on connection: {:?}", peer_id.map(|p| p.to_string()), connection_id);
                    },
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        println!("Connection closed with peer: {}. Cause: {:?}", peer_id, cause);
                    }
                    SwarmEvent::OutgoingConnectionError { connection_id, peer_id, error } => {
                        println!(
                            "Outgoing connection error to peer: {:?}, connection_id: {:?}, error: {}",
                            peer_id,
                            connection_id,
                            error
                        );
                    }
                    _ => {}
                }
            }
            _ = heartbeat_interval.tick() => {
                // Always use the local multiaddr for heartbeats in this setup
                let current_multiaddr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", config.node.port, peer_id);

                // Send heartbeat with current local information
                match send_heartbeat(
                    &agent,
                    &canister_id,
                    node_principal,
                    &config.node.name,
                    &current_multiaddr, // Use current_multiaddr here
                ).await {
                    Ok(success) => {
                        if success {
                            println!("Heartbeat sent successfully");
                        } else {
                            println!("Heartbeat failed, will retry in next interval");
                        }
                    }
                    Err(e) => println!("Error sending heartbeat: {}", e),
                }
            }
            _ = signing_request_interval.tick() => {
                let mesh_peers_count = swarm.behaviour().gossipsub.mesh_peers(&topic.hash()).count();
                if mesh_peers_count > 0 {
                    println!("Initiating automated signing request ({} mesh peers).", mesh_peers_count);

                    // Generate timestamped message content
                    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    let message_content = format!("Auto Sign Request @ {}", timestamp);

                    // Create hash of the message content
                    let mut hasher = Sha256::new();
                    hasher.update(message_content.as_bytes());
                    let message_hash_bytes = hasher.finalize();
                    let message_hash_hex = hex::encode(message_hash_bytes);

                    // Create the SignedMessage struct
                    let mut initial_signatures = HashSet::new();
                    initial_signatures.insert(local_peer_id.to_string()); // Add own signature

                    let signed_message = SignedMessage {
                        content: message_content.to_string(),
                        originator_id: local_peer_id.to_string(),
                        message_hash: message_hash_hex.clone(),
                        signatures: initial_signatures,
                    };

                    // Store locally
                    let mut store = message_store_clone.lock().unwrap(); 
                    // Avoid duplicate requests for the same hash quickly
                    if !store.contains_key(&message_hash_hex) {
                        store.insert(message_hash_hex.clone(), signed_message.clone());
                        drop(store); // Release lock before publishing

                        // Serialize and publish via Gossipsub
                        match serde_json::to_string(&signed_message) {
                            Ok(json_message) => {
                                if let Err(e) = swarm
                                    .behaviour_mut().gossipsub
                                    .publish(topic.clone(), json_message.as_bytes())
                                {
                                    println!("Publish error for auto-sign request: {e:?}");
                                }
                                println!("Auto-sign message published: Hash {}", message_hash_hex);
                            }
                            Err(e) => {
                                println!("Error serializing auto-sign message: {}", e);
                            }
                        }
                    } else {
                        // Optionally log that we skipped an existing hash
                        // println!("Skipping publish for existing hash: {}", message_hash_hex);
                        drop(store);
                    }
                } else {
                    // println!("Skipping automated signing request: No mesh peers."); // Optional log
                }
            }
        }
    }
}
