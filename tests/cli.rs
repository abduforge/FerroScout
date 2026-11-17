use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_file(name: &str, contents: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "ferroscout-cli-{}-{nonce}-{name}",
        std::process::id()
    ));
    fs::write(&path, contents).unwrap();
    path
}

#[test]
fn clean_scan_exits_zero() {
    let path = temp_file("clean.py", "print('hello')\n");
    let status = Command::new(env!("CARGO_BIN_EXE_ferroscout"))
        .args(["scan", path.to_str().unwrap()])
        .status()
        .unwrap();
    fs::remove_file(path).unwrap();
    assert_eq!(status.code(), Some(0));
}

#[test]
fn finding_scan_exits_one() {
    let path = temp_file("tls.py", "requests.get(url, verify=False)\n");
    let status = Command::new(env!("CARGO_BIN_EXE_ferroscout"))
        .args(["scan", path.to_str().unwrap()])
        .status()
        .unwrap();
    fs::remove_file(path).unwrap();
    assert_eq!(status.code(), Some(1));
}

#[test]
fn invalid_path_exits_two() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("ferroscout-does-not-exist-{nonce}"));
    let status = Command::new(env!("CARGO_BIN_EXE_ferroscout"))
        .args(["scan", path.to_str().unwrap()])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}

#[test]
fn sarif_output_is_valid_json() {
    let path = temp_file("sarif.py", "print('hello')\n");
    let output = Command::new(env!("CARGO_BIN_EXE_ferroscout"))
        .args(["scan", path.to_str().unwrap(), "--format", "sarif"])
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();
    assert_eq!(output.status.code(), Some(0));
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["version"], "2.1.0");
    assert_eq!(document["runs"][0]["tool"]["driver"]["name"], "FerroScout");
}
