use std::{error::Error, hash::{Hash, Hasher},collections::hash_map::DefaultHasher, collections::{HashSet, HashMap, VecDeque}, fs::{File, OpenOptions}, path::Path, io::{self, BufWriter, Read, Write}, env, sync::{Arc, Mutex}, time::{SystemTime, UNIX_EPOCH}, net::UdpSocket};
use serde::{Deserialize, Serialize};
use futures::prelude::*;
use libp2p::{identity, noise, ping, gossipsub, mdns, swarm::{SwarmEvent, NetworkBehaviour}, tcp, yamux, Multiaddr, PeerId, multiaddr::Protocol};
use tracing_subscriber::EnvFilter;
use ic_agent::{Agent};
use candid::{CandidType, Principal, Deserialize as CandidDeserialize};
use tokio::time::{interval, Duration};
use sha2::{Sha256, Digest};
use hex;
use serde_json;
use chrono::Utc; // Add chrono for timestamps
use std::time::Instant; // Import Instant for duration checking if needed later
use rand::random;

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

type MessageStore = Arc<Mutex<HashMap<String, SignedMessage>>>;
type VerificationCounter = Arc<Mutex<u64>>;
type FailedPublishQueue = Arc<Mutex<VecDeque<SignedMessage>>>; // Use VecDeque for FIFO retry

// Log file structure
type LogFile = Arc<Mutex<BufWriter<File>>>; // Use BufWriter for efficiency

// Add network metrics structure
#[derive(Debug, Default)]
struct NetworkMetrics {
    connection_attempts: u64,
    successful_connections: u64,
    failed_connections: u64,
    connection_durations: Vec<Duration>,
    message_latencies: Vec<Duration>,
    mesh_peer_counts: Vec<usize>,
    last_heartbeat_time: Option<Instant>,
}

async fn write_log(log_file: &LogFile, message: String) {
    let mut writer = log_file.lock().unwrap();
    if let Err(e) = writeln!(writer, "[{}] {}", Utc::now().to_rfc3339(), message) {
        eprintln!("Failed to write to verification log: {}", e); // Log errors to stderr
    }
    // Flush occasionally might be needed if logs are critical in case of crash
    // writer.flush().ok();
}

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
    // println!("Fetched nodes from canister: {:?}", nodes);
    
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

async fn get_public_ip() -> Result<String, Box<dyn Error>> {
    // Try to get public IP from environment first
    if let Ok(ip) = env::var("PUBLIC_IP") {
        return Ok(ip);
    }

    // Try to get public IP by connecting to a public service
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?; // Google's DNS
    let local_addr = socket.local_addr()?;
    let ip = local_addr.ip().to_string();
    
    println!("Detected public IP: {}", ip);
    Ok(ip)
}

async fn clear_registry(agent: &Agent, canister_id: &Principal) -> Result<bool, Box<dyn Error>> {
    let response = agent
        .update(canister_id, "clear_registry")
        .with_arg(candid::encode_args(())?)
        .call_and_wait()
        .await?;

    let result: bool = candid::decode_one(&response)?;
    Ok(result)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let config = load_config()?;
    println!("Loaded configuration: {:?}", config);

    // Check if we should clear the registry
    if env::var("CLEAR_REGISTRY").is_ok() {
        let ic_url = env::var("IC_URL").unwrap_or_else(|_| {
            println!("Warning: IC_URL environment variable not set, using URL from config.yaml");
            config.node.ic.url.clone()
        });
        println!("Using IC URL: {}", ic_url);

        let agent = Agent::builder()
            .with_url(&ic_url)
            .build()?;

        if config.node.ic.is_local {
            agent.fetch_root_key().await?;
        }

        let canister_id = Principal::from_text(&config.node.ic.canister_id)?;
        println!("Clearing registry for canister: {}", canister_id);

        match clear_registry(&agent, &canister_id).await {
            Ok(true) => println!("Registry cleared successfully"),
            Ok(false) => println!("Failed to clear registry"),
            Err(e) => println!("Error clearing registry: {}", e),
        }
        return Ok(());
    }

    // --- Log File Setup ---
    let log_path = "verification_log.txt";
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    let log_file: LogFile = Arc::new(Mutex::new(BufWriter::new(file)));
    println!("Logging verification events to: {}", log_path);
    // --- End Log File Setup ---

    let private_key_bytes = hex::decode(&config.node.private_key)?;
    let id_keys = identity::Keypair::ed25519_from_bytes(private_key_bytes.clone())?;
    let peer_id = PeerId::from(id_keys.public());
    println!("Peer ID: {}", peer_id);

    let node_principal = Principal::self_authenticating(&private_key_bytes);
    println!("Node Principal ID: {}", node_principal);

    let message_store: MessageStore = Arc::new(Mutex::new(HashMap::new()));
    let verification_counter: VerificationCounter = Arc::new(Mutex::new(0));
    let failed_publish_queue: FailedPublishQueue = Arc::new(Mutex::new(VecDeque::new()));

    let ic_url = env::var("IC_URL").unwrap_or_else(|_| {
        println!("Warning: IC_URL environment variable not set, using URL from config.yaml");
        config.node.ic.url.clone()
    });
    println!("Using IC URL: {}", ic_url);

    let agent = Agent::builder()
        .with_url(&ic_url)
        .build()?;

    if config.node.ic.is_local {
        agent.fetch_root_key().await?;
    }

    let canister_id = Principal::from_text(&config.node.ic.canister_id)?;
    println!("Canister ID: {}", canister_id);

    // Get the public IP address
    let public_ip = get_public_ip().await?;
    let public_multiaddr = format!("/ip4/{}/tcp/{}/p2p/{}", public_ip, config.node.port, peer_id);
    println!("Using public multiaddress for registration/heartbeat: {}", public_multiaddr);

    match register_node(
        &agent,
        &canister_id,
        node_principal,
        &config.node.name,
        &public_multiaddr,
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

    let fetched_nodes = fetch_peer_nodes(&agent, &config.node).await?;
    // println!("Fetched Peer Nodes from canister: {:?}", fetched_nodes);

    let active_nodes: Vec<String> = fetched_nodes
        .into_iter()
        .filter(|addr_str| {
            if let Ok(ma) = addr_str.parse::<Multiaddr>() {
                if let Some(Protocol::P2p(fetched_peer_id)) = ma.iter().last() {
                    if fetched_peer_id != peer_id { 
                        return true;
                    }
                }
            }
            println!("Discarding own address or invalid address: {}", addr_str);
            false
        })
        .collect();

    // println!("Filtered Peer Nodes (excluding self): {:?}", active_nodes);

    let dialable_node_addrs: Vec<String> = active_nodes.iter().map(|addr_str| { 
        if let Ok(ma) = addr_str.parse::<Multiaddr>() {
            let components: Vec<_> = ma.iter().collect();
            if let Some(Protocol::Ip4(ip)) = components.get(0) {
                if !ip.is_loopback() && !ip.is_private() {
                    // Keep the original address
                    return addr_str.clone();
                }
            }
        }
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
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .mesh_n_low(3)
                .mesh_n(5)
                .mesh_n_high(8)
                .mesh_outbound_min(2)
                .gossip_lazy(4)
                .do_px()
                .flood_publish(true)
                // Add these for better debugging:
                .heartbeat_initial_delay(Duration::from_secs(1))
                .heartbeat_interval(Duration::from_secs(1))
                .build()
                .map_err(io::Error::other)?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            // Get mDNS port from environment variable or use default
            let _mdns_port = env::var("MDNS_PORT")
                .ok()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(5353);

            // Create mDNS config with custom settings
            let mdns_config = mdns::Config {
                ttl: std::time::Duration::from_secs(60), // 60 second TTL
                query_interval: std::time::Duration::from_secs(10), // Query every 10 seconds
                enable_ipv6: false, // Disable IPv6 to avoid potential issues
            };

            let mdns = mdns::tokio::Behaviour::new(mdns_config, key.public().to_peer_id())?;

            let ping = ping::Behaviour::new(ping::Config::new());

            Ok(MyBehaviour { gossipsub, mdns, ping })
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();

    let topic = gossipsub::IdentTopic::new("testing");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    println!("Subscribed to topic: {}", topic.hash());

    // Create listen address using public IP
    let listen_addr = format!("/ip4/{}/tcp/{}", public_ip, config.node.port).parse()?;
    swarm.listen_on(listen_addr)?;

    let mut target_peers = HashSet::new(); 
    for addr in &dialable_node_addrs { 
        if let Ok(remote_addr) = addr.parse::<Multiaddr>() {
            if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = remote_addr.iter().last() {
                target_peers.insert(peer_id);
                match swarm.dial(remote_addr.clone()) {
                    Ok(_) => {
                        println!("Dialing active node: {}", addr);
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

    let mut heartbeat_interval = interval(Duration::from_secs(60));
    let mut signing_request_interval = interval(Duration::from_secs(10)); 
    let mut retry_publish_interval = interval(Duration::from_secs(30)); // Added retry interval

    let network_metrics: Arc<Mutex<NetworkMetrics>> = Arc::new(Mutex::new(NetworkMetrics::default()));
    let metrics_clone = network_metrics.clone();
    
    // Add metrics logging interval
    let mut metrics_interval = interval(Duration::from_secs(60));

    println!("Node initialized. Waiting for peers and network events.");

    let message_store_clone = message_store.clone();
    let verification_counter_clone = verification_counter.clone();
    let failed_publish_queue_clone = failed_publish_queue.clone();
    let local_peer_id = peer_id;
    let _keypair_clone = id_keys; // Prefix with underscore
    let log_file_clone = log_file.clone(); // Clone Arc for the main loop

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("\nNode Information:");
                        println!("Name: {}", config.node.name);
                        println!("PeerId: {}", local_peer_id);
                        println!("Listening on: {}", address);
                        println!("Public Multiaddr: {}", public_multiaddr);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        println!("Connection established with peer: {}", peer_id);
                        println!("Connected via: {}", endpoint.get_remote_address());
                                            
                        // Immediately add to explicit peers
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        
                        // Force mesh addition if below target
                        let mesh_peers = swarm.behaviour().gossipsub.mesh_peers(&topic.hash()).count();
                        if mesh_peers < 5 {
                            println!("Mesh size low ({}), forcing peer {} into mesh", mesh_peers, peer_id);
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            
                            // Send a test message to trigger mesh formation
                            let test_msg = format!("FORCE-MESH {} {}", peer_id, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), test_msg.as_bytes()) {
                                println!("Failed to publish force-mesh message: {}", e);
                            }
                        }
                        
                        let mut metrics = metrics_clone.lock().unwrap();
                        metrics.successful_connections += 1;
                        metrics.connection_attempts += 1;
                        metrics.connection_durations.push(Duration::from_secs(0));
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, _multiaddr) in list {
                            println!("mDNS discovered a new peer: {peer_id}");
                            // Add mDNS discovered peers to explicit peers
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            let mesh_peers = swarm.behaviour().gossipsub.mesh_peers(&topic.hash()).count();
                            if mesh_peers < 5 {
                                println!("Mesh size below target ({} < 5), added mDNS peer {}", mesh_peers, peer_id);
                                // The mesh will be updated in the next heartbeat
                            }
                        }
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                        for (peer_id, _multiaddr) in list {
                            println!("mDNS discover peer has expired: {peer_id}");
                            // Keep remove_explicit_peer if you added them previously,
                            // but since we removed the adding part, this might also be unnecessary
                            // unless other parts of the code add explicit peers. Let's keep it for now.
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message_id: _id,
                        message,
                    })) => {
                        let log_file_inner_clone = log_file_clone.clone(); // Clone for this specific event
                        let local_peer_id_str = local_peer_id.to_string(); // Get local peer id as string

                        if let Ok(received_message) = serde_json::from_slice::<SignedMessage>(&message.data) {
                            // println!("Received SignedMessage: Hash {} from Peer {}", received_message.message_hash, propagation_source); // Keep for debugging if needed

                            let mut store = message_store_clone.lock().unwrap();
                            let message_hash = received_message.message_hash.clone();
                            let initial_sig_count_before_update = store.get(&message_hash).map_or(0, |m| m.signatures.len());

                            let entry = store.entry(message_hash.clone()).or_insert_with(|| {
                                // println!("Adding new message entry for hash: {}", message_hash); // Keep for debugging if needed
                                received_message.clone()
                            });

                            let mut signatures_added_now = HashSet::new();
                            let sender_peer_id_str = propagation_source.to_string();

                            // Add signatures from the received message payload
                            // Iterate over a reference (&) to avoid moving signatures
                            for sig_peer_id in &received_message.signatures {
                                if entry.signatures.insert(sig_peer_id.clone()) {
                                    signatures_added_now.insert(sig_peer_id.clone()); // Clone here as we need ownership for the set
                                }
                            }

                            // Add the signature of the peer who propagated the message to us
                            let mut sender_added = false;
                            if entry.signatures.insert(sender_peer_id_str.clone()) {
                                signatures_added_now.insert(sender_peer_id_str.clone());
                                sender_added = true;
                            }

                            let current_sig_count = entry.signatures.len();
                            let signatures_added_str = signatures_added_now.iter().cloned().collect::<Vec<_>>().join(",");

                            // Log reception and signature processing
                            write_log(
                                &log_file_inner_clone,
                                format!(
                                    "MSG_RECV Node={} From={} Hash={} PayloadSigs={} AddedNow=[{}] SenderAdded={} TotalSigs={}",
                                    local_peer_id_str,
                                    sender_peer_id_str,
                                    message_hash,
                                    received_message.signatures.len(), // Now valid to access .len()
                                    signatures_added_str,
                                    sender_added,
                                    current_sig_count
                                )
                            ).await;


                            // Check for verification threshold
                            let mut needs_republish = !signatures_added_now.is_empty(); // Republish if any new sig was added

                            if current_sig_count >= 3 && initial_sig_count_before_update < 3 {
                                let mut counter = verification_counter_clone.lock().unwrap();
                                *counter += 1;
                                println!("*** MESSAGE VERIFIED ({} signatures): Hash {} (Total Verified: {}) ***", current_sig_count, message_hash, *counter);
                                // Log verification
                                write_log(
                                    &log_file_inner_clone,
                                    format!(
                                        "MSG_VERIFIED Node={} Hash={} SigCount={} TotalVerifiedCount={}",
                                        local_peer_id_str,
                                        message_hash,
                                        current_sig_count,
                                        *counter
                                    )
                                ).await;

                                needs_republish = false; // Don't republish if just verified
                            } else if current_sig_count >= 3 {
                                needs_republish = false; // Already verified, no need to republish
                            }

                            if needs_republish {
                               // println!("Republishing message with updated signatures: Hash {}", message_hash); // Keep for debugging
                               write_log(
                                   &log_file_inner_clone,
                                   format!("MSG_REPUBLISH Node={} Hash={} NewSigCount={}", local_peer_id_str, message_hash, current_sig_count)
                               ).await;

                                match serde_json::to_string(&*entry) {
                                    Ok(json_message) => {
                                        if let Err(e) = swarm
                                            .behaviour_mut().gossipsub
                                            .publish(topic.clone(), json_message.as_bytes())
                                        {
                                            eprintln!("Republish error: {e:?}. Queuing for retry.");
                                            failed_publish_queue_clone.lock().unwrap().push_back(entry.clone());
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("Error serializing message for republish: {}. Queuing for retry.", e);
                                        failed_publish_queue_clone.lock().unwrap().push_back(entry.clone());
                                    }
                                }
                            }

                            let mut metrics = metrics_clone.lock().unwrap();
                            metrics.message_latencies.push(Duration::from_secs(0)); // You can measure actual latency if needed
                        } else {
                            println!(
                                "Got plain text message: '{}' from peer: {}",
                                String::from_utf8_lossy(&message.data),
                                propagation_source
                            );
                        }
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Ping(_event)) => { // Prefix with underscore
                        // println!("Ping event: {:?}", event);
                    },
                    SwarmEvent::Dialing { peer_id, connection_id } => {
                        println!("Dialing peer: {:?} on connection: {:?}", peer_id.map(|p| p.to_string()), connection_id);
                    },
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        println!("Connection closed with peer: {}. Cause: {:?}", peer_id, cause);
                    }
                    SwarmEvent::OutgoingConnectionError { connection_id: _, peer_id: _, error: _ } => {
                        let mut metrics = metrics_clone.lock().unwrap();
                        metrics.failed_connections += 1;
                        metrics.connection_attempts += 1;
                    },
                    _ => {}
                }
            }
            _ = heartbeat_interval.tick() => {
                // Refresh public IP on each heartbeat
                let current_ip = get_public_ip().await?;
                let current_multiaddr = format!("/ip4/{}/tcp/{}/p2p/{}", current_ip, config.node.port, local_peer_id);
                match send_heartbeat(
                    &agent,
                    &canister_id,
                    node_principal,
                    &config.node.name,
                    &current_multiaddr,
                ).await {
                    Ok(success) => {
                        if success {
                           // println!("Heartbeat sent successfully"); // Reduce noise
                        } else {
                            println!("Heartbeat failed, will retry in next interval");
                        }
                    }
                    Err(e) => println!("Error sending heartbeat: {}", e),
                }

                let mut metrics = metrics_clone.lock().unwrap();
                metrics.last_heartbeat_time = Some(Instant::now());
                let mesh_peers = swarm.behaviour().gossipsub.mesh_peers(&topic.hash()).count();
                println!("Current mesh size: {}", mesh_peers);
                metrics.mesh_peer_counts.push(mesh_peers);
            }
            _ = signing_request_interval.tick() => {
                let mesh_peers_count = swarm.behaviour().gossipsub.mesh_peers(&topic.hash()).count();
                // Check if the mesh peer count meets the threshold of 3
                if mesh_peers_count >= 3 {
                    println!("Initiating automated signing request ({} mesh peers >= 3).", mesh_peers_count);
                    let log_file_inner_clone = log_file_clone.clone(); // Clone only if needed

                    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    let message_content = format!("Auto Sign Request @ {}", timestamp);

                    let mut hasher = Sha256::new();
                    hasher.update(message_content.as_bytes());
                    let message_hash_bytes = hasher.finalize();
                    let message_hash_hex = hex::encode(message_hash_bytes);

                    let mut initial_signatures = HashSet::new();
                    let local_peer_id_str = local_peer_id.to_string();
                    initial_signatures.insert(local_peer_id_str.clone());

                    let signed_message = SignedMessage {
                        content: message_content.to_string(),
                        originator_id: local_peer_id_str.clone(),
                        message_hash: message_hash_hex.clone(),
                        signatures: initial_signatures,
                    };

                    let mut store = message_store_clone.lock().unwrap();
                    if !store.contains_key(&message_hash_hex) {
                        store.insert(message_hash_hex.clone(), signed_message.clone());
                        drop(store); // Release lock before async operations

                        match serde_json::to_string(&signed_message) {
                            Ok(json_message) => {
                                if let Err(e) = swarm
                                    .behaviour_mut().gossipsub
                                    .publish(topic.clone(), json_message.as_bytes())
                                {
                                    eprintln!("Publish error for auto-sign request: {e:?}. Queuing for retry.");
                                    failed_publish_queue_clone.lock().unwrap().push_back(signed_message);
                                } else {
                                   // println!("Auto-sign message published: Hash {}", message_hash_hex);
                                   // Log initial publication
                                   write_log(
                                        &log_file_inner_clone, // Use the cloned log file handle
                                        format!("MSG_PUBLISH_INIT Node={} Hash={} Content='{}'", local_peer_id_str, message_hash_hex, signed_message.content)
                                    ).await;
                                }
                            }
                            Err(e) => {
                                 eprintln!("Error serializing auto-sign message: {}. Queuing for retry.", e);
                                 failed_publish_queue_clone.lock().unwrap().push_back(signed_message);
                            }
                        }
                    } else {
                        drop(store); // Release lock if message already exists
                    }
                } else {
                    // Log that we are skipping because the threshold isn't met
                    println!("Skipping automated signing request: Need >= 3 mesh peers, have {}.", mesh_peers_count);
                }
            }
            _ = retry_publish_interval.tick() => { // Added retry logic arm
                let mut queue = failed_publish_queue_clone.lock().unwrap();
                if !queue.is_empty() {
                    println!("Retrying publication for {} queued messages.", queue.len());
                    let mut still_failed = VecDeque::new(); // Collect messages that fail again
                    while let Some(message_to_retry) = queue.pop_front() {
                        match serde_json::to_string(&message_to_retry) {
                            Ok(json_message) => {
                                if let Err(e) = swarm
                                    .behaviour_mut().gossipsub
                                    .publish(topic.clone(), json_message.as_bytes())
                                {
                                    println!("Retry publish error for hash {}: {e:?}. Re-queuing.", message_to_retry.message_hash);
                                    still_failed.push_back(message_to_retry); // Add back if publish fails
                                } else {
                                    println!("Retry publish successful for hash {}.", message_to_retry.message_hash);
                                }
                            }
                            Err(e) => {
                                println!("Retry serialization error for hash {}: {}. Re-queuing.", message_to_retry.message_hash, e);
                                still_failed.push_back(message_to_retry); // Add back if serialization fails
                            }
                        }
                    }
                    // Put messages that failed again back into the main queue
                    queue.extend(still_failed);
                }
            }
            _ = metrics_interval.tick() => {
                let metrics = metrics_clone.lock().unwrap();
                let mesh_peers = swarm.behaviour().gossipsub.mesh_peers(&topic.hash()).count();
                
                // Calculate average connection duration
                let avg_connection_duration = if !metrics.connection_durations.is_empty() {
                    metrics.connection_durations.iter().sum::<Duration>() / metrics.connection_durations.len() as u32
                } else {
                    Duration::from_secs(0)
                };
                
                // Calculate average message latency
                let avg_message_latency = if !metrics.message_latencies.is_empty() {
                    metrics.message_latencies.iter().sum::<Duration>() / metrics.message_latencies.len() as u32
                } else {
                    Duration::from_secs(0)
                };
                
                // Log network metrics
                println!("\n=== Network Metrics ===");
                println!("Connection Success Rate: {:.2}%", 
                    (metrics.successful_connections as f64 / metrics.connection_attempts as f64) * 100.0);
                println!("Average Connection Duration: {:?}", avg_connection_duration);
                println!("Average Message Latency: {:?}", avg_message_latency);
                println!("Current Mesh Size: {}", mesh_peers);
                println!("Mesh Size History (last 5): {:?}", 
                    metrics.mesh_peer_counts.iter().rev().take(5).collect::<Vec<_>>());
                println!("Last Heartbeat: {:?}", metrics.last_heartbeat_time);
                println!("=====================\n");
            }
        }

        // Add mesh formation check in the main loop
        let peer_ids: Vec<PeerId> = swarm.connected_peers().cloned().collect();
        let mesh_peers: HashSet<PeerId> = swarm.behaviour().gossipsub.mesh_peers(&topic.hash()).cloned().collect();
        
        for peer_id in peer_ids {
            if !mesh_peers.contains(&peer_id) {
                println!("Peer {} is connected but not in mesh, attempting to force mesh addition", peer_id);
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                
                // Generate unique message with timestamp and random number
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
                let random_num: u64 = random();
                let test_message = format!("Mesh test {} {} {}", peer_id, timestamp, random_num);
                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), test_message.as_bytes()) {
                    println!("Failed to publish test message: {}", e);
                }
                
                if mesh_peers.len() < 5 {
                    println!("Mesh size below target ({} < 5), attempting to force peer {} into mesh", 
                        mesh_peers.len(), peer_id);
                }
            }
        }
    }
}
