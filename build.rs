use std::process::Command;

fn main() {
    // 1. Dynamic UTC ISO-8601 Timestamp
    let timestamp = match Command::new("date").args(["-u", "+%Y-%m-%dT%H:%M:%SZ"]).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => "2026-09-04T05:00:00Z".to_string(),
    };

    // 2. Dynamic Git Commit SHA (Checks env var first, then git with safe.directory override)
    let git_commit = if let Ok(val) = std::env::var("SUBZERO_GIT_COMMIT") {
        val
    } else {
        match Command::new("git")
            .args(["-c", "safe.directory=*", "rev-parse", "--short", "HEAD"])
            .output()
        {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            }
            _ => "musl-reproducible".to_string(),
        }
    };

    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", timestamp);
    println!("cargo:rustc-env=GIT_COMMIT={}", git_commit);
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=Cargo.toml");
}
