use libp2p::{
    request_response::{RequestResponse, RequestResponseCodec, RequestResponseEvent, RequestResponseMessage},
    swarm::derive_prelude::FromSwarm,
    StreamProtocol,
    core::upgrade,
    ping,
    PeerId,
    identity::Keypair,
    swarm::{NetworkBehaviour, derive_prelude::*},
};
use serde::{Serialize, Deserialize};
use serde_json;
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH, Duration},
    collections::{HashMap, HashSet},
    error::Error as StdError,
};

// Define our protocol
pub const SIGNING_PROTOCOL: StreamProtocol = StreamProtocol::new("/message-signing/1.0.0");

// Define our message types
#[derive(Debug, Serialize, Deserialize)]
pub struct SigningRequest {
    pub message: String,
    pub timestamp: u64,
    pub initiator: Vec<u8>, // Serialized PeerId
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigningResponse {
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SigningProtocolMessage {
    Request(SigningRequest),
    Response(SigningResponse),
}

// Implement the Codec for our protocol
#[derive(Clone)]
pub struct SigningCodec;

#[derive(Debug)]
pub enum CodecError {
    Io(io::Error),
    Serialization(serde_json::Error),
}

impl RequestResponseCodec for SigningCodec {
    type Protocol = StreamProtocol;
    type Request = SigningRequest;
    type Response = SigningResponse;

    fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> Result<Self::Request, CodecError>
    where
        T: io::Read + Send + Sync,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).map_err(CodecError::Io)?;
        serde_json::from_slice(&buf).map_err(CodecError::Serialization)
    }

    fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> Result<Self::Response, CodecError>
    where
        T: io::Read + Send + Sync,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).map_err(CodecError::Io)?;
        serde_json::from_slice(&buf).map_err(CodecError::Serialization)
    }

    fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> Result<(), CodecError>
    where
        T: io::Write + Send + Sync,
    {
        let buf = serde_json::to_vec(&req).map_err(CodecError::Serialization)?;
        io.write_all(&buf).map_err(CodecError::Io)
    }

    fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Self::Response) -> Result<(), CodecError>
    where
        T: io::Write + Send + Sync,
    {
        let buf = serde_json::to_vec(&res).map_err(CodecError::Serialization)?;
        io.write_all(&buf).map_err(CodecError::Io)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "SigningBehaviourEvent")]
pub struct SigningBehaviour {
    request_response: RequestResponse<SigningCodec>,
    ping: ping::Behaviour,
    #[behaviour(ignore)]
    keypair: Keypair,
    #[behaviour(ignore)]
    pending_requests: HashMap<PeerId, SigningRequest>,
    #[behaviour(ignore)]
    active_signatures: HashMap<String, HashSet<PeerId>>, // message_id -> signers
}

#[derive(Debug)]
pub enum SigningBehaviourEvent {
    RequestResponse(RequestResponseEvent<SigningRequest, SigningResponse>),
    Ping(ping::Event),
}

impl From<RequestResponseEvent<SigningRequest, SigningResponse>> for SigningBehaviourEvent {
    fn from(event: RequestResponseEvent<SigningRequest, SigningResponse>) -> Self {
        SigningBehaviourEvent::RequestResponse(event)
    }
}

impl From<ping::Event> for SigningBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        SigningBehaviourEvent::Ping(event)
    }
}

impl SigningBehaviour {
    pub fn new(keypair: Keypair) -> Self {
        let timeout = Duration::from_secs(30);
        let request_response = RequestResponse::new(
            SigningCodec,
            vec![(SIGNING_PROTOCOL, libp2p::core::upgrade::Version::V1)],
            libp2p::request_response::Config::default()
                .with_request_timeout(timeout)
                .with_max_concurrent_streams(100),
        );

        Self {
            request_response,
            ping: ping::Behaviour::new(ping::Config::new()),
            keypair,
            pending_requests: HashMap::new(),
            active_signatures: HashMap::new(),
        }
    }

    pub fn request_signature(&mut self, peer: PeerId, message: String) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let request = SigningRequest {
            message: message.clone(),
            timestamp,
            initiator: self.keypair.public().to_peer_id().to_bytes(),
        };

        // Store the request for verification when response comes
        self.pending_requests.insert(peer, request.clone());

        // Track which peers we've asked to sign this message
        self.active_signatures
            .entry(message)
            .or_default()
            .insert(peer);

        self.request_response
            .send_request(&peer, request);

        Ok(())
    }

    fn verify_and_sign(&self, request: &SigningRequest) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Verify the message isn't too old (e.g., within 5 minutes)
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if now - request.timestamp > 300 {
            return Err("Message too old".into());
        }

        // Verify the initiator is a valid PeerId
        let initiator = PeerId::from_bytes(&request.initiator)?;

        // Serialize the request for signing
        let serialized = serde_json::to_vec(&request)?;

        // Sign with our keypair
        let signature = self.keypair.sign(&serialized)?;

        Ok(signature)
    }
}