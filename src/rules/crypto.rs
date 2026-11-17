use super::make_finding;
use crate::models::{Confidence, Severity};
use regex::Regex;
use std::path::Path;

pub fn check(path: &Path, content: &str) -> Vec<crate::models::Finding> {
    let weak_password_hash = Regex::new(
        r"(?i)(?:md5|sha1)\s*\([^\n]*(?:password|passwd|credential)|(?:password|passwd|credential)[^\n]*(?:md5|sha1)",
    )
    .expect("literal regex is valid");
    let weak_random = Regex::new(
        r"(?i)Math\.random\s*\(\s*\)[^\n]*(?:token|secret|key)|(?:token|secret|key)[^\n]*Math\.random\s*\(",
    )
    .expect("literal regex is valid");
    let mut findings = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if weak_password_hash.is_match(line) {
            findings.push(make_finding(
                path, index + 1, "FS-CRYPTO-001", Severity::Medium,
                "Weak hash appears to be used for password material", Some("CWE-916"), Confidence::Medium,
                line,
                "MD5 or SHA-1 and a password-related identifier occur on the same line. The analyzer cannot establish whether this is authentication storage or a non-security checksum.",
                "Fast legacy hashes are unsuitable for password storage and can make offline guessing substantially easier.",
                "Use a password-hashing algorithm designed for password storage, such as Argon2id, scrypt, or bcrypt, with a unique salt and appropriate parameters.",
            ));
        }
        if weak_random.is_match(line) {
            findings.push(make_finding(
                path, index + 1, "FS-CRYPTO-001", Severity::Medium,
                "Non-cryptographic randomness appears to generate a security value", Some("CWE-338"), Confidence::Medium,
                line,
                "Math.random() appears near a token, secret, or key identifier. The actual use and downstream safeguards are unknown.",
                "Predictable values may be guessable if they are used as authentication tokens, secrets, or cryptographic keys.",
                "Use the operating system cryptographically secure random-number generator or the platform's established cryptographic API.",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_md5_password_hashing() {
        assert_eq!(
            check(Path::new("auth.py"), "digest = hashlib.md5(password)\n").len(),
            1
        );
    }

    #[test]
    fn detects_math_random_for_token() {
        assert_eq!(
            check(Path::new("token.js"), "const token = Math.random();\n").len(),
            1
        );
    }

    #[test]
    fn ignores_checksum_use() {
        assert!(check(
            Path::new("checksum.py"),
            "digest = hashlib.md5(file_bytes)\n"
        )
        .is_empty());
    }
}
