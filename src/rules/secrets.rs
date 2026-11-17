use super::make_finding;
use crate::models::{Confidence, Severity};
use regex::Regex;
use std::path::Path;

pub fn check(path: &Path, content: &str) -> Vec<crate::models::Finding> {
    let assignment = Regex::new(
        r#"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|password|passwd|client[_-]?secret|secret)\b["']?\s*[:=]\s*["']?([A-Za-z0-9_./+=:-]{8,})"#,
    )
    .expect("literal regex is valid");
    let bearer = Regex::new(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/-]{12,}")
        .expect("literal regex is valid");
    let pem = Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").expect("literal regex is valid");
    let mut findings = Vec::new();

    for (index, line) in content.lines().enumerate() {
        let found = assignment
            .captures(line)
            .and_then(|captures| captures.get(1))
            .is_some_and(|value| !is_placeholder(value.as_str()));
        if found {
            findings.push(make_finding(
                path,
                index + 1,
                "FS-SECRET-001",
                Severity::High,
                "Potential hardcoded credential",
                Some("CWE-798"),
                Confidence::Medium,
                line,
                "A credential-like assignment contains a non-placeholder value. Static analysis cannot determine whether it is active or production data.",
                "If the value is real and committed, repository readers may be able to reuse it to access the associated service or account.",
                "Move credentials to an appropriate secret store or protected runtime configuration. Rotate the value if it was real, and keep it out of version control.",
            ));
        } else if bearer.is_match(line) {
            findings.push(make_finding(
                path,
                index + 1,
                "FS-SECRET-001",
                Severity::High,
                "Bearer token appears in source or a captured HTTP sample",
                Some("CWE-798"),
                Confidence::Medium,
                line,
                "An Authorization header contains a bearer-token-like value. Static analysis cannot determine whether the token is active.",
                "If the token is valid, a reader of this file may be able to reuse its associated access privileges.",
                "Remove the token from the file, store credentials outside source control, and revoke or rotate it if it was real.",
            ));
        } else if pem.is_match(line) {
            findings.push(make_finding(
                path,
                index + 1,
                "FS-SECRET-001",
                Severity::High,
                "Private key material appears in source",
                Some("CWE-321"),
                Confidence::High,
                "[PRIVATE KEY MATERIAL REDACTED]",
                "A PEM private-key marker appears in a scanned file.",
                "A committed private key may allow impersonation or decryption, depending on how it is used.",
                "Remove the key from source control, store it in a protected key-management system, and rotate it if it was exposed.",
            ));
        }
    }
    findings
}

fn is_placeholder(value: &str) -> bool {
    let value = value
        .trim()
        .trim_matches(&['\'', '"', '`'][..])
        .to_ascii_lowercase();
    let exact = [
        "changeme",
        "change-me",
        "change_me",
        "placeholder",
        "example",
        "sample",
        "dummy",
        "test",
        "testing",
        "password",
        "secret",
        "your-token",
        "your_api_key",
        "none",
        "null",
        "undefined",
        "xxxxxxxx",
        "12345678",
        "replace_me",
        "replace-me",
    ];
    exact.contains(&value.as_str())
        || value.contains("your_")
        || value.contains("example_")
        || value.contains("placeholder")
        || value.contains("dummy")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_and_redacts_non_placeholder_secret() {
        let findings = check(Path::new("settings.env"), "API_KEY=live_key_123456789\n");
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].evidence.contains("live_key_123456789"));
        assert!(findings[0].evidence.contains("REDACTED"));
    }

    #[test]
    fn ignores_placeholder_secret() {
        let findings = check(
            Path::new("example.env"),
            "API_KEY=change_me\nTOKEN=your-token\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn redacts_private_key_marker() {
        let findings = check(Path::new("id_rsa"), "-----BEGIN RSA PRIVATE KEY-----\n");
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].evidence.contains("RSA"));
    }

    #[test]
    fn detects_and_redacts_bearer_token() {
        let findings = check(
            Path::new("capture.http"),
            "Authorization: Bearer very_secret_token_12345\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].evidence.contains("very_secret_token_12345"));
    }
}
