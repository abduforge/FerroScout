use super::make_finding;
use crate::models::{Confidence, Severity};
use regex::Regex;
use std::path::Path;

pub fn check(path: &Path, content: &str) -> Vec<crate::models::Finding> {
    let debug = Regex::new(
        r"(?i)(?:DEBUG\s*=\s*true|debug\s*:\s*true|app\.run\s*\([^)]*debug\s*=\s*true|runserver\s+--insecure)",
    )
    .expect("literal regex is valid");
    let mut findings = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if debug.is_match(line) {
            findings.push(make_finding(
                path, index + 1, "FS-DEBUG-001", Severity::Low,
                "Application debug mode appears to be enabled", Some("CWE-489"), Confidence::Medium,
                line,
                "A debug-mode setting appears enabled. The analyzer cannot determine whether this configuration is used in production or exposed to untrusted users.",
                "If enabled in a production environment, debug interfaces or detailed error output may disclose implementation details or sensitive data.",
                "Disable debug mode in production. Load environment-specific settings explicitly and add a deployment check that rejects debug configuration in production.",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_flask_debug_mode() {
        assert_eq!(check(Path::new("app.py"), "app.run(debug=True)\n").len(), 1);
    }

    #[test]
    fn ignores_debug_false() {
        assert!(check(Path::new("app.py"), "app.run(debug=False)\n").is_empty());
    }
}
