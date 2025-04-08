use std::{error::Error, time::Duration, fs::{File, OpenOptions}, path::Path, io::{Read, Write}};
use serde::{Deserialize, Serialize};
use futures::prelude::*;
use libp2p::{identity, noise, ping, swarm::SwarmEvent, tcp, yamux, Multiaddr, PeerId};
use tracing_subscriber::EnvFilter;
use ic_agent::{Agent, identity::BasicIdentity};
use candid::{CandidType, Principal, Decode, IDLArgs, Deserialize as CandidDeserialize};
use tokio::time::interval;


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

async fn get_public_ip() -> Option<String> {
    if let Some(ip) = public_ip::addr().await {
        Some(ip.to_string())
    } else {
        None
    }
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

    // Create IC agent with proper configuration
    let agent = Agent::builder()
        .with_url(&config.node.ic.url)
        .build()?;

    // Always fetch root key for local development
    if config.node.ic.is_local {
        agent.fetch_root_key().await?;
    }

    // Get the canister ID from config
    let canister_id = Principal::from_text(&config.node.ic.canister_id)?;
    println!("Canister ID: {}", canister_id);

    // Get initial public IP
    let initial_ip = get_public_ip().await;
    let initial_multiaddr = if let Some(ip) = &initial_ip {
        format!("/ip4/{}/tcp/{}/p2p/{}", ip, config.node.port, peer_id)
    } else {
        format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", config.node.port, peer_id)
    };

    // Attempt initial registration
    if let Some(ip) = &initial_ip {
        match register_node(
            &agent,
            &canister_id,
            node_principal,
            &config.node.name,
            &initial_multiaddr,
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
    }

    // Fetch active peer nodes from the canister
    let active_nodes = fetch_peer_nodes(&agent, &config.node).await?;
    println!("Active Peer Nodes: {:?}", active_nodes);

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| ping::Behaviour::default())?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();

    // Use configured port
    let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", config.node.port).parse()?;
    swarm.listen_on(listen_addr)?;

    // Connect to active nodes
    for addr in &active_nodes {
        if let Ok(remote) = addr.parse::<Multiaddr>() {
            swarm.dial(remote)?;
            println!("Connected to active node: {}", addr);
        }
    }

    let mut last_ip = initial_ip.unwrap_or_default();
    let mut heartbeat_interval = interval(Duration::from_secs(30));

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
                    SwarmEvent::Behaviour(event) => println!("{event:?}"),
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        println!("Connection established with peer: {}", peer_id);
                        println!("Connected via: {}", endpoint.get_remote_address());
                    }
                    _ => {}
                }
            }
            _ = heartbeat_interval.tick() => {
                if let Some(public_ip) = get_public_ip().await {
                    let multiaddr = format!("/ip4/{}/tcp/{}/p2p/{}", public_ip, config.node.port, peer_id);
                    
                    // Only send heartbeat if IP has changed
                    if public_ip != last_ip {
                        println!("IP changed from {} to {}, updating registration", last_ip, public_ip);
                    }
                    
                    // Send heartbeat with current information
                    match send_heartbeat(
                        &agent,
                        &canister_id,
                        node_principal,
                        &config.node.name,
                        &multiaddr,
                    ).await {
                        Ok(success) => {
                            if success {
                                println!("Heartbeat sent successfully");
                                last_ip = public_ip;
                            } else {
                                println!("Heartbeat failed, will retry in next interval");
                            }
                        }
                        Err(e) => println!("Error sending heartbeat: {}", e),
                    }
                }
            }
        }
    }
}
