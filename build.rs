use std::{env, process::Command};

fn main() {
    let commit = Command::new("git")
        .arg("rev-parse")
        .arg("--short")
        .arg("HEAD")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or(String::from("unknown"));
    let commit_sha = commit.trim();

    println!("cargo:rustc-env=GIT_HASH={commit_sha}");
    println!(
        "cargo:rustc-env=DET_VERSION_FULL={}-{}-{} (Build: {commit_sha})",
        env!("CARGO_PKG_VERSION"),
        env::consts::OS,
        env::consts::ARCH
    );
}
