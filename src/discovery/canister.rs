use ic_agent::Agent;
use candid::{Principal, encode_args, Decode};
use crate::types::messages::{BootstrapNode, RegisterResponse};
use crate::utils::current_timestamp;

// Connect to IC canister
pub fn connect_to_ic(ic_config: &crate::types::ICSettings) -> Result<Agent, Box<dyn std::error::Error + Send + Sync>> {
    let agent = Agent::builder()
        .with_url(&ic_config.url)
        .build()?;

    // Don't await here - will fetch root key when needed
    Ok(agent)
}

// Register a bootstrap node with the canister
pub async fn register_bootstrap_node(
    agent: &Agent, 
    canister_id: &Principal, 
    node_principal: Principal, 
    name: &str, 
    multiaddr: &str
) -> Result<RegisterResponse, Box<dyn std::error::Error + Send + Sync>> {
    // Fetch root key for local replica
    if ic_config_is_local(agent) {
        agent.fetch_root_key().await?;
    }

    let response = agent
        .update(canister_id, "register_node")
        .with_arg(encode_args((
            name,
            multiaddr,
            node_principal,
        ))?)
        .call_and_wait()
        .await?;

    let result: RegisterResponse = Decode!(&response, RegisterResponse)?;
    Ok(result)
}

// Send heartbeat to the canister
pub async fn send_heartbeat(
    agent: &Agent, 
    canister_id: &Principal, 
    node_principal: Principal, 
    name: &str, 
    multiaddr: &str
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    // Fetch root key for local replica
    if ic_config_is_local(agent) {
        agent.fetch_root_key().await?;
    }

    let response = agent
        .update(canister_id, "heartbeat")
        .with_arg(encode_args((
            node_principal,
            name,
            multiaddr,
        ))?)
        .call_and_wait()
        .await?;

    let result: bool = Decode!(&response, bool)?;
    Ok(result)
}

// Fetch bootstrap nodes from the canister
pub async fn fetch_bootstrap_nodes(agent: &Agent, canister_id: &Principal) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    // Fetch root key for local replica
    if ic_config_is_local(agent) {
        agent.fetch_root_key().await?;
    }

    let response = agent
        .query(canister_id, "get_nodes")
        .with_arg(encode_args(())?)
        .call()
        .await?;

    let nodes: Vec<BootstrapNode> = Decode!(&response, Vec<BootstrapNode>)?;
    
    // Filter out nodes that haven't sent a heartbeat in the last 5 minutes
    let current_time = current_timestamp();
    let active_nodes: Vec<String> = nodes
        .into_iter()
        .filter(|node| current_time - node.last_heartbeat < 300) // 5 minutes
        .map(|node| node.multiaddress)
        .collect();
    
    Ok(active_nodes)
}

// Clear the registry (for testing)
pub async fn clear_registry(agent: &Agent, canister_id: &Principal) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    // Fetch root key for local replica
    if ic_config_is_local(agent) {
        agent.fetch_root_key().await?;
    }

    let response = agent
        .update(canister_id, "clear_registry")
        .with_arg(encode_args(())?)
        .call_and_wait()
        .await?;

    let result: bool = Decode!(&response, bool)?;
    Ok(result)
}

// Helper function to check if we're working with a local replica
fn ic_config_is_local(_agent: &Agent) -> bool {
    // For now, just assume true for simplicity
    // In production, you would need to properly check this
    true
} 