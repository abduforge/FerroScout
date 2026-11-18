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

#[test]
fn markdown_output_uses_markdown_heading() {
    let path = temp_file("markdown.py", "print('hello')\n");
    let output = Command::new(env!("CARGO_BIN_EXE_ferroscout"))
        .args(["scan", path.to_str().unwrap(), "--format", "markdown"])
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.starts_with("# FerroScout Security Report"));
}

#[test]
fn excluded_rule_is_counted_and_does_not_fail_the_scan() {
    let path = temp_file("exclude-rule.py", "requests.get(url, verify=False)\n");
    let output = Command::new(env!("CARGO_BIN_EXE_ferroscout"))
        .args([
            "scan",
            path.to_str().unwrap(),
            "--exclude-rule",
            "FS-TLS-001",
        ])
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Filtered by CLI options: 1"));
}

#[test]
fn unknown_excluded_rule_is_rejected() {
    let path = temp_file("unknown-rule.py", "print('hello')\n");
    let output = Command::new(env!("CARGO_BIN_EXE_ferroscout"))
        .args([
            "scan",
            path.to_str().unwrap(),
            "--exclude-rule",
            "FS-NOT-REAL",
        ])
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown rule ID"));
}
