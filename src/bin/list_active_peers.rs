use std::{error::Error};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use ic_agent::Agent;
use candid::{Principal, CandidType};

#[derive(Debug, Deserialize)]
struct NodeConfig {
    node: NodeSettings,
}

#[derive(Debug, Deserialize)]
struct NodeSettings {
    name: String,
    port: u16,
    private_key: String,
    ic: ICSettings,
    peer_nodes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ICSettings {
    canister_id: String,
    is_local: bool,
    url: String,
}

#[derive(CandidType, Deserialize, Debug)]
struct Node {
    name: String,
    principal: Principal,
    multiaddress: String,
    last_heartbeat: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Load configuration
    let config_path = Path::new("config.yaml");
    let file = File::open(config_path)?;
    let config: NodeConfig = serde_yaml::from_reader(file)?;

    // Create IC agent
    let agent = Agent::builder()
        .with_url(&config.node.ic.url)
        .build()?;

    if config.node.ic.is_local {
        agent.fetch_root_key().await?;
    }

    let canister_id = Principal::from_text(&config.node.ic.canister_id)?;
    
    // Query active nodes from the canister
    println!("Querying active nodes from canister {}...\n", canister_id);
    
    let response = agent
        .query(&canister_id, "get_nodes")
        .with_arg(candid::encode_args(()).unwrap())
        .call()
        .await?;

    let nodes: Vec<Node> = candid::decode_one(&response)?;
    
    if nodes.is_empty() {
        println!("No active nodes found in the network");
    } else {
        println!("Active nodes in the network:");
        for node in nodes {
            println!("\nNode: {}", node.name);
            println!("Principal: {}", node.principal);
            println!("Address: {}", node.multiaddress);
            println!("Last heartbeat: {} seconds ago", 
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
                    .saturating_sub(node.last_heartbeat)
            );
        }
    }

    Ok(())
} 