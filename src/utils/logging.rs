use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use chrono::Utc;
use rand::random;

// Type alias for log file
pub type LogFile = Arc<Mutex<BufWriter<File>>>;

// Set up logging to a file and return a handle
pub fn setup_logging(log_file_path: &str) -> Result<LogFile, Box<dyn std::error::Error + Send + Sync>> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(log_file_path)?;
    
    let log_file = Arc::new(Mutex::new(BufWriter::new(file)));
    
    // Write initial log entry
    {
        let mut writer = log_file.lock().unwrap();
        writeln!(writer, "[{}] P2P node started", Utc::now().to_rfc3339())?;
        writer.flush()?;
    }
    
    Ok(log_file.clone())
}

// Write a log entry with timestamp
pub async fn write_log(log_file: &LogFile, message: &str) {
    let timestamp = Utc::now().to_rfc3339();
    
    if let Ok(mut writer) = log_file.lock() {
        if let Err(e) = writeln!(writer, "[{}] {}", timestamp, message) {
            eprintln!("Failed to write to log: {}", e);
        }
        
        // Don't flush on every write for performance
        if random::<u8>() < 5 { // ~2% chance to flush
            if let Err(e) = writer.flush() {
                eprintln!("Failed to flush log: {}", e);
            }
        }
    }
} 