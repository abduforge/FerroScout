use super::make_finding;
use crate::models::{Confidence, Severity};
use regex::Regex;
use std::path::Path;

pub fn check(path: &Path, content: &str) -> Vec<crate::models::Finding> {
    let sink = Regex::new(
        r"(?i)(\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write\s*\()",
    )
    .expect("literal regex is valid");
    let source = Regex::new(
        r"(?i)(req(?:uest)?\.(?:body|query|params)|request\.(?:args|form|GET|POST)|location\.(?:search|hash)|searchParams|user[_A-Z]?input|untrusted)",
    )
    .expect("literal regex is valid");
    let sanitizer = Regex::new(r"(?i)(DOMPurify|sanitize|escapeHtml|textContent)")
        .expect("literal regex is valid");
    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();

    for (index, line) in lines.iter().enumerate() {
        if !sink.is_match(line) {
            continue;
        }
        let start = index.saturating_sub(3);
        let context = lines[start..=index].join(" ");
        if source.is_match(&context) && !sanitizer.is_match(&context) {
            findings.push(make_finding(
                path,
                index + 1,
                "FS-XSS-001",
                Severity::Medium,
                "Untrusted input appears near a dangerous HTML sink",
                Some("CWE-79"),
                Confidence::Medium,
                line,
                "A known untrusted-input marker occurs within three preceding lines of a dynamic HTML sink. The limited pattern check does not prove that the same value reaches the sink.",
                "If attacker-controlled data reaches this sink without context-appropriate sanitization, browser script execution may be possible.",
                "Prefer textContent or framework-safe rendering. If HTML is required, use a maintained context-aware sanitizer and verify the full data flow.",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_input_near_inner_html() {
        let code = "const userInput = req.query.name;\nelement.innerHTML = userInput;\n";
        assert_eq!(check(Path::new("app.js"), code).len(), 1);
    }

    #[test]
    fn ignores_static_html_assignment() {
        let code = "element.innerHTML = '<b>Welcome</b>';\n";
        assert!(check(Path::new("app.js"), code).is_empty());
    }

    #[test]
    fn ignores_sanitized_nearby_input() {
        let code = "const userInput = req.query.name;\nconst clean = DOMPurify.sanitize(userInput);\nelement.innerHTML = clean;\n";
        assert!(check(Path::new("app.js"), code).is_empty());
    }
}
