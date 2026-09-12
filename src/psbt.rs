use bitcoin::psbt::Psbt;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::io::{BufRead, BufReader};
use std::str::FromStr;

pub fn parse_psbt(input: &str) -> Result<Psbt, String> {
    let input = input.trim();
    
    // Try parsing as base64
    if let Ok(bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input) {
        if let Ok(psbt) = Psbt::deserialize(&bytes) {
            return Ok(psbt);
        }
    }
    
    // Try parsing as hex if base64 fails
    if let Ok(bytes) = hex::decode(input) {
        if let Ok(psbt) = Psbt::deserialize(&bytes) {
            return Ok(psbt);
        }
    }
    
    Err("Failed to parse PSBT from base64 or hex".into())
}

pub fn spawn_zbarcam() -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    
    thread::spawn(move || {
        let mut child = match Command::new("zbarcam")
            .args(["--raw", "--nodisplay", "/dev/video0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => {
                let _ = tx.send("Error: Failed to start zbarcam. Please ensure zbar-tools is installed and /dev/video0 exists.".into());
                return;
            }
        };

        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(l) = line {
                    if !l.trim().is_empty() {
                        let _ = tx.send(l);
                    }
                }
            }
        }
        
        let _ = child.wait();
    });
    
    rx
}
