use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use candid::{CandidType, Deserialize as CandidDeserialize, Principal};

// Message with signatures for consensus
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedMessage {
    pub content: String,
    pub originator_id: String,
    pub message_hash: String,
    pub signatures: HashSet<String>,
}

// Bootstrap node information from registry
#[derive(Debug, Serialize, Deserialize, CandidType, Clone)]
pub struct BootstrapNode {
    pub name: String,
    pub principal: Principal,
    pub multiaddress: String,
    pub last_heartbeat: u64,
}

// Response from node registration
#[derive(Debug, Serialize, Deserialize, CandidType, Clone)]
pub struct RegisterResponse {
    pub success: bool,
    pub principal: Principal,
}

// Network protocol message types
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum NetworkMessage {
    Hello {
        peer_id: String,
        timestamp: u64,
    },
    BootstrapRequest {
        peer_id: String,
    },
    BootstrapResponse {
        peers: Vec<String>, // Multiaddresses
    },
    DirectPing {
        peer_id: String,
        timestamp: u64,
    },
} 