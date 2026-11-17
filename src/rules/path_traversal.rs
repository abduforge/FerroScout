use super::make_finding;
use crate::models::{Confidence, Severity};
use regex::Regex;
use std::path::Path;

pub fn check(path: &Path, content: &str) -> Vec<crate::models::Finding> {
    let sink = Regex::new(
        r"(?i)\b(?:open|readFile|readFileSync|createReadStream|send_file|File::open|read_to_string)\s*\([^;]*",
    )
    .expect("literal regex is valid");
    let untrusted = Regex::new(
        r"(?i)(req(?:uest)?\.(?:body|query|params)|request\.(?:args|form)|user[_A-Z]?input|params\.|query\.)",
    )
    .expect("literal regex is valid");
    let mut findings = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if sink.is_match(line) && untrusted.is_match(line) {
            findings.push(make_finding(
                path, index + 1, "FS-PATH-001", Severity::Medium,
                "Untrusted data appears in a filesystem path operation", Some("CWE-22"), Confidence::Medium,
                line,
                "A filesystem operation and a user-controlled input marker occur on the same line. The analyzer cannot establish whether canonicalization or root-directory containment is enforced elsewhere.",
                "If the supplied path is not constrained to an intended directory, path traversal may expose or modify files available to the application.",
                "Resolve the path against a fixed base directory, canonicalize it where appropriate, and verify that the final path remains inside the allowed root. Prefer allowlisted identifiers over arbitrary paths.",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_user_controlled_file_path() {
        let code = "fs.readFileSync(req.query.path);\n";
        assert_eq!(check(Path::new("server.js"), code).len(), 1);
    }

    #[test]
    fn ignores_fixed_file_path() {
        let code = "fs.readFileSync('/var/data/report.txt');\n";
        assert!(check(Path::new("server.js"), code).is_empty());
    }
}
