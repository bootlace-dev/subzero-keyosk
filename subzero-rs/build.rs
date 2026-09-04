use std::process::Command;

fn main() {
    // 1. Dynamic UTC ISO-8601 Timestamp
    let timestamp = match Command::new("date").args(["-u", "+%Y-%m-%dT%H:%M:%SZ"]).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => "2026-09-04T05:00:00Z".to_string(),
    };

    // 2. Dynamic Git Commit SHA
    let git_commit = match Command::new("git").args(["rev-parse", "--short", "HEAD"]).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => "musl-reproducible".to_string(),
    };

    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", timestamp);
    println!("cargo:rustc-env=GIT_COMMIT={}", git_commit);
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=Cargo.toml");
}
