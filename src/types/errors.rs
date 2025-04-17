use std::error::Error;
use std::fmt;

// Custom error type for P2P operations
#[derive(Debug)]
pub enum P2pError {
    IoError(std::io::Error),
    SerializationError(String),
    NetworkError(String),
    CandidError(String),
    ConfigError(String),
    AgentError(String),
    GossipsubError(String),
    KademliaError(String),
}

impl fmt::Display for P2pError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            P2pError::IoError(e) => write!(f, "I/O error: {}", e),
            P2pError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            P2pError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            P2pError::CandidError(msg) => write!(f, "Candid error: {}", msg),
            P2pError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            P2pError::AgentError(msg) => write!(f, "Agent error: {}", msg),
            P2pError::GossipsubError(msg) => write!(f, "Gossipsub error: {}", msg),
            P2pError::KademliaError(msg) => write!(f, "Kademlia error: {}", msg),
        }
    }
}

impl Error for P2pError {}

// Implement From for common error types
impl From<std::io::Error> for P2pError {
    fn from(error: std::io::Error) -> Self {
        P2pError::IoError(error)
    }
}

impl From<serde_json::Error> for P2pError {
    fn from(error: serde_json::Error) -> Self {
        P2pError::SerializationError(error.to_string())
    }
}

impl From<candid::Error> for P2pError {
    fn from(error: candid::Error) -> Self {
        P2pError::CandidError(error.to_string())
    }
}

impl From<ic_agent::AgentError> for P2pError {
    fn from(error: ic_agent::AgentError) -> Self {
        P2pError::AgentError(error.to_string())
    }
}

// Handle Gossipsub and Kademlia errors
pub fn handle_gossipsub_error<E: std::fmt::Display>(error: E) -> P2pError {
    P2pError::GossipsubError(error.to_string())
}

pub fn handle_kademlia_error<E: std::fmt::Display>(error: E) -> P2pError {
    P2pError::KademliaError(error.to_string())
}

pub fn handle_network_error<E: std::fmt::Display>(error: E) -> P2pError {
    P2pError::NetworkError(error.to_string())
} 