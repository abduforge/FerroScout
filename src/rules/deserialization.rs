use super::make_finding;
use crate::models::{Confidence, Severity};
use regex::Regex;
use std::path::Path;

pub fn check(path: &Path, content: &str) -> Vec<crate::models::Finding> {
    let unsafe_api = Regex::new(
        r"(?i)(pickle\.(?:load|loads)\s*\(|yaml\.(?:load|unsafe_load)\s*\(|Marshal\.load\s*\()",
    )
    .expect("literal regex is valid");
    let safe_loader =
        Regex::new(r"(?i)(SafeLoader|safe_load|safe_load_all)").expect("literal regex is valid");
    let mut findings = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if unsafe_api.is_match(line) && !safe_loader.is_match(line) {
            findings.push(make_finding(
                path, index + 1, "FS-DESER-001", Severity::Medium,
                "Potentially unsafe deserialization API", Some("CWE-502"), Confidence::Medium,
                line,
                "A known unsafe deserialization API appears in the source. Whether the serialized input is attacker-controlled is not established.",
                "Deserializing untrusted data with APIs capable of object construction may lead to code execution or unexpected object behavior, depending on the language and library.",
                "Do not deserialize untrusted data with pickle or equivalent object-instantiating APIs. Prefer restricted data formats and safe loaders, and validate the input schema.",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pickle_load() {
        assert_eq!(
            check(Path::new("cache.py"), "obj = pickle.loads(payload)\n").len(),
            1
        );
    }

    #[test]
    fn ignores_yaml_safe_load() {
        assert!(check(Path::new("config.py"), "config = yaml.safe_load(data)\n").is_empty());
    }
}
