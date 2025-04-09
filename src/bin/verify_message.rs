use std::{error::Error, collections::HashMap, time::Duration};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use ic_agent::{
    Agent, 
    agent::http_transport::ReqwestHttpReplicaV2Transport,
    identity::AnonymousIdentity
};
use candid::{Principal, CandidType};
use libp2p::identity;
use tokio::time::timeout;
use futures::future::join_all;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Message to verify
    #[arg(short, long)]
    message: Option<String>,

    /// Timeout in seconds for signature collection
    #[arg(short, long, default_value_t = 30)]
    timeout: u64,

    /// Minimum number of required signatures
    #[arg(short = 'n', long, default_value_t = 3)]
    min_signatures: usize,
}

#[derive(Debug, Deserialize)]
struct NodeConfig {
    node: NodeSettings,
}

#[derive(Debug, Deserialize)]
struct NodeSettings {
    ic: ICSettings,
    private_key: String,
}

#[derive(Debug, Deserialize)]
struct ICSettings {
    network: String,
    canister_id: String,
    is_local: bool,
    url: String,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
struct Node {
    principal: Principal,
    name: String,
    last_heartbeat: u64,
    multiaddress: String,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
struct VerificationRequest {
    message: Vec<u8>,
    requesting_principal: Principal,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
struct VerificationResponse {
    signature: Vec<u8>,
    signer_principal: Principal,
}

async fn get_active_nodes(agent: &Agent, canister_id: &Principal) -> Result<Vec<Node>, Box<dyn Error>> {
    let response = agent
        .query(canister_id, "get_nodes")
        .with_arg(candid::encode_args(()).unwrap())
        .call()
        .await?;

    let nodes: Vec<Node> = candid::decode_one(&response)?;
    Ok(nodes)
}

async fn request_signature(agent: &Agent, canister_id: &Principal, message: &[u8], requesting_principal: Principal) -> Result<VerificationResponse, Box<dyn Error>> {
    let request = VerificationRequest {
        message: message.to_vec(),
        requesting_principal,
    };

    // Add retry logic with exponential backoff
    let mut retries = 0;
    let max_retries = 3;
    let mut delay = Duration::from_millis(100);

    loop {
        match agent
            .update(canister_id, "request_signature")
            .with_arg(candid::encode_args((request.clone(),))?)
            .call_and_wait()
            .await
        {
            Ok(response) => {
                match candid::decode_one(&response) {
                    Ok(verification_response) => return Ok(verification_response),
                    Err(e) => {
                        println!("Failed to decode response: {:?}", e);
                        if retries >= max_retries {
                            return Err(format!("Failed to decode response after {} retries: {:?}", max_retries, e).into());
                        }
                    }
                }
            }
            Err(e) => {
                println!("Request failed: {:?}", e);
                if retries >= max_retries {
                    return Err(format!("Request failed after {} retries: {:?}", max_retries, e).into());
                }
            }
        }

        retries += 1;
        tokio::time::sleep(delay).await;
        delay *= 2; // Exponential backoff
    }
}

fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, Box<dyn Error>> {
    // Convert the public key bytes to a libp2p public key
    let mut key_bytes = public_key.to_vec();
    let keypair = identity::Keypair::ed25519_from_bytes(&mut key_bytes)?;
    let public_key = keypair.public();
    
    // Verify the signature
    Ok(public_key.verify(message, signature))
}

async fn collect_signature(
    agent: &Agent,
    canister_id: &Principal,
    node: &Node,
    message: &[u8],
    requesting_principal: Principal,
) -> Result<Option<(Principal, Vec<u8>)>, Box<dyn Error>> {
    println!("Requesting signature from node: {} ({})", node.name, node.principal);
    
    match request_signature(agent, canister_id, message, requesting_principal).await {
        Ok(response) => {
            println!("Received signature from node: {}", node.name);
            // Verify the signature before accepting it
            match verify_signature(message, &response.signature, &node.principal.as_slice().to_vec()) {
                Ok(is_valid) => {
                    if is_valid {
                        println!("Signature from {} is valid", node.name);
                        Ok(Some((response.signer_principal, response.signature)))
                    } else {
                        println!("Warning: Invalid signature from {}", node.name);
                        Ok(None)
                    }
                }
                Err(e) => {
                    println!("Error verifying signature from {}: {}", node.name, e);
                    Ok(None)
                }
            }
        }
        Err(e) => {
            println!("Failed to get signature from {}: {}", node.name, e);
            Ok(None)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Load configuration
    let config_path = Path::new("config.yaml");
    let file = File::open(config_path).map_err(|e| format!("Failed to open config file: {}", e))?;
    let config: NodeConfig = serde_yaml::from_reader(file)
        .map_err(|e| format!("Failed to parse config file: {}", e))?;

    // Generate a keypair and create identity
    let mut private_key_bytes = hex::decode(&config.node.private_key)
        .map_err(|e| format!("Failed to decode private key: {}", e))?;
    let keypair = identity::Keypair::ed25519_from_bytes(&mut private_key_bytes)
        .map_err(|e| format!("Failed to create keypair: {}", e))?;
    
    // Generate Principal ID from the private key bytes
    let my_principal = Principal::self_authenticating(&private_key_bytes);
    println!("Using principal: {}", my_principal);

    // Create IC agent with proper transport and anonymous identity
    let transport = ReqwestHttpReplicaV2Transport::create(&config.node.ic.url)
        .map_err(|e| format!("Failed to create transport: {}", e))?;
    let agent = Agent::builder()
        .with_transport(transport)
        .with_identity(AnonymousIdentity)
        .build()
        .map_err(|e| format!("Failed to create agent: {}", e))?;

    // Initialize the agent
    if config.node.ic.is_local {
        agent.fetch_root_key().await
            .map_err(|e| format!("Failed to fetch root key: {}", e))?;
    }

    let canister_id = Principal::from_text(&config.node.ic.canister_id)
        .map_err(|e| format!("Failed to parse canister ID: {}", e))?;
    
    // Get the message to be signed
    let message = args.message
        .map(|m| m.into_bytes())
        .unwrap_or_else(|| b"Hello, this is a test message that needs verification".to_vec());
    println!("Message to be verified: {}", String::from_utf8_lossy(&message));

    // Get active nodes
    let nodes = get_active_nodes(&agent, &canister_id).await
        .map_err(|e| format!("Failed to get active nodes: {}", e))?;
    println!("Found {} active nodes", nodes.len());
    
    if nodes.len() < args.min_signatures {
        return Err(format!("Not enough active nodes for verification (minimum {} required)", args.min_signatures).into());
    }

    println!("\nCollecting signatures from nodes...");
    let mut signatures = HashMap::new();

    // Create futures for all signature requests
    let signature_futures: Vec<_> = nodes.iter()
        .map(|node| collect_signature(&agent, &canister_id, node, &message, my_principal))
        .collect();

    // Wait for all signatures with timeout
    match timeout(Duration::from_secs(args.timeout), join_all(signature_futures)).await {
        Ok(results) => {
            for result in results {
                match result {
                    Ok(Some((principal, signature))) => {
                        signatures.insert(principal, signature);
                    }
                    Ok(None) => continue,
                    Err(e) => println!("Error collecting signature: {}", e),
                }
            }
        }
        Err(_) => println!("Timeout waiting for signatures after {} seconds", args.timeout),
    }

    // Check if we have enough signatures
    if signatures.len() >= args.min_signatures {
        println!("\nMessage verification successful!");
        println!("Verified by {} nodes:", signatures.len());
        for (principal, _) in &signatures {
            if let Some(node) = nodes.iter().find(|n| n.principal == *principal) {
                println!("- {}", node.name);
            }
        }
    } else {
        println!("\nFailed to collect enough valid signatures");
        println!("Only received {} valid signatures, need at least {}", 
            signatures.len(), args.min_signatures);
    }

    Ok(())
} 