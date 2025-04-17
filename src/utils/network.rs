use std::env;
use std::error::Error;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

// Get the current time as seconds since UNIX epoch
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

// Get the public IP address, first from environment variables then by detection
pub async fn get_public_ip() -> Result<String, Box<dyn Error + Send + Sync>> {
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