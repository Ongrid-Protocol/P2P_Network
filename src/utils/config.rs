use std::fs::{File, OpenOptions};
use std::path::Path;
use std::io::{self, Read, Write};
use std::env;

use crate::types::{NodeConfig, NodeType, P2pError, ICSettings};
use candid::Principal;

// Load configuration from YAML file
pub fn load_config() -> Result<NodeConfig, Box<dyn std::error::Error + Send + Sync>> {
    let config_path = Path::new("config.yaml");
    let file = File::open(config_path)?;
    
    // Parse the config
    let mut config: NodeConfig = serde_yaml::from_reader(file)?;
    
    // Determine node type from environment or default to Regular
    if let Ok(node_type) = env::var("NODE_TYPE") {
        match node_type.to_lowercase().as_str() {
            "bootstrap" => config.node_type = NodeType::Bootstrap,
            "regular" => config.node_type = NodeType::Regular,
            _ => return Err(Box::new(P2pError::ConfigError(format!("Invalid node type: {}", node_type))))
        }
    }
    
    // If it's a bootstrap node, ensure bootstrap_nodes includes itself
    if config.node_type == NodeType::Bootstrap {
        // If this is a bootstrap node, ensure the bootstrap_nodes are properly set
        if config.bootstrap_nodes.is_empty() {
            let public_ip = match env::var("PUBLIC_IP") {
                Ok(ip) => ip,
                Err(_) => "127.0.0.1".to_string()
            };
            let self_addr = format!("/ip4/{}/tcp/{}", public_ip, config.port);
            config.bootstrap_nodes.push(self_addr);
        }
    }
    
    // Override IC URL from environment if provided
    if let Ok(ic_url) = env::var("IC_URL") {
        config.ic.url = ic_url;
    }

    Ok(config)
}

// Save principal ID for future reference
pub fn save_principal_id(principal: &Principal) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("node_principal.txt")?;
    
    file.write_all(principal.to_string().as_bytes())?;
    println!("Saved principal ID: {}", principal);
    Ok(())
}

// Load principal ID if previously saved
pub fn load_principal_id() -> Result<Option<Principal>, Box<dyn std::error::Error + Send + Sync>> {
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