use std::process::Command;

fn main() {
    // 1. Deterministic UTC ISO-8601 Timestamp (Checks SOURCE_DATE_EPOCH first, then env, then git commit date)
    let timestamp = if let Ok(epoch_str) = std::env::var("SOURCE_DATE_EPOCH") {
        if let Ok(epoch_secs) = epoch_str.trim().parse::<i64>() {
            match Command::new("date").args(["-u", "-d", &format!("@{}", epoch_secs), "+%Y-%m-%dT%H:%M:%SZ"]).output() {
                Ok(output) if output.status.success() => {
                    String::from_utf8_lossy(&output.stdout).trim().to_string()
                }
                _ => "2026-09-04T05:00:00Z".to_string(),
            }
        } else {
            "2026-09-04T05:00:00Z".to_string()
        }
    } else if let Ok(val) = std::env::var("SUBZERO_BUILD_TIMESTAMP") {
        val
    } else if let Ok(val) = std::env::var("BUILD_TIMESTAMP") {
        val
    } else {
        match Command::new("git").args(["-c", "safe.directory=*", "log", "-1", "--format=%cI"]).output() {
            Ok(output) if output.status.success() => {
                let git_date = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !git_date.is_empty() {
                    git_date
                } else {
                    "2026-09-04T05:00:00Z".to_string()
                }
            }
            _ => "2026-09-04T05:00:00Z".to_string(),
        }
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
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-env-changed=SUBZERO_BUILD_TIMESTAMP");
    println!("cargo:rerun-if-env-changed=BUILD_TIMESTAMP");
    println!("cargo:rerun-if-env-changed=SUBZERO_GIT_COMMIT");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/");
}
