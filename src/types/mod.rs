pub mod messages;
pub mod errors;

use serde::{Deserialize, Serialize};
use candid::{CandidType, Principal, Deserialize as CandidDeserialize};
use std::collections::HashSet;
use std::time::{Instant, Duration};

#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
pub enum NodeType {
    Bootstrap,
    Regular
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NodeConfig {
    pub node_type: NodeType,
    pub name: String,
    pub port: u16,
    pub private_key: String,
    pub ic: ICSettings,
    pub bootstrap_nodes: Vec<String>, // Used by regular nodes
    pub peer_nodes: Vec<String>,      // Legacy field
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ICSettings {
    pub network: String,
    pub canister_id: String,
    pub is_local: bool,
    pub url: String,
}

// Network metrics structure
#[derive(Debug, Default)]
pub struct NetworkMetrics {
    pub connection_attempts: u64,
    pub successful_connections: u64,
    pub failed_connections: u64,
    pub connection_durations: Vec<Duration>,
    pub message_latencies: Vec<Duration>,
    pub mesh_peer_counts: Vec<usize>,
    pub last_heartbeat_time: Option<Instant>,
}

// Re-export the types from the submodules
pub use messages::SignedMessage;
pub use errors::P2pError; 