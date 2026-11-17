use super::make_finding;
use crate::models::{Confidence, Severity};
use regex::Regex;
use std::path::Path;

pub fn check(path: &Path, content: &str) -> Vec<crate::models::Finding> {
    let sql_sink = Regex::new(r"(?i)\b(?:execute|execute_query|query|raw|raw_sql)\s*\(")
        .expect("literal regex is valid");
    let dynamic =
        Regex::new(r#"(?i)(format!\s*\(|\.format\s*\(|\bf["']|\+\s*[A-Za-z_]|\$\{[^}]+\})"#)
            .expect("literal regex is valid");
    let shell_sink = Regex::new(
        r"(?i)(os\.system\s*\(|os\.popen\s*\(|child_process\.exec(?:Sync)?\s*\(|execSync\s*\(|subprocess\.(?:run|Popen|call)\s*\(|shell\s*=\s*true)",
    )
    .expect("literal regex is valid");
    let shell_dynamic = Regex::new(r#"(?i)(format!\s*\(|\bf["']|\+\s*[A-Za-z_]|\$\{|request\.|req\.|user[_A-Z]?input|input\s*\()"#)
        .expect("literal regex is valid");
    let mut findings = Vec::new();

    for (index, line) in content.lines().enumerate() {
        if sql_sink.is_match(line) && dynamic.is_match(line) {
            findings.push(make_finding(
                path, index + 1, "FS-INJECT-001", Severity::Medium,
                "Dynamic data appears in SQL query construction", Some("CWE-89"), Confidence::Medium,
                line,
                "A query-like call and a string interpolation or concatenation pattern occur on the same line. Parameter binding and surrounding code were not fully evaluated.",
                "If untrusted input is interpolated into SQL syntax, an attacker may alter the intended query.",
                "Use parameterized queries or prepared statements. Keep SQL structure separate from user-controlled values and review the complete query construction path.",
            ));
        }
        if shell_sink.is_match(line) && shell_dynamic.is_match(line) {
            findings.push(make_finding(
                path, index + 1, "FS-INJECT-001", Severity::High,
                "Dynamic data appears in a shell command operation", Some("CWE-78"), Confidence::Medium,
                line,
                "A shell-execution API and a dynamic-data marker occur on the same line. This pattern is a review lead, not proof that attacker-controlled input is exploitable.",
                "If untrusted input is interpreted by a shell, command syntax may be altered and unintended commands may run.",
                "Avoid shell command strings. Use argument arrays with a fixed executable, validate each argument against an allowlist, and do not pass untrusted content through a shell.",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_dynamic_sql_construction() {
        let code = "db.query(format!(\"SELECT * FROM users WHERE name = {}\", name));\n";
        assert_eq!(check(Path::new("db.rs"), code).len(), 1);
    }

    #[test]
    fn finds_dynamic_shell_execution() {
        let code = "subprocess.run(f\"tool {request.args}\", shell=True)\n";
        assert_eq!(check(Path::new("worker.py"), code).len(), 1);
    }

    #[test]
    fn ignores_parameterized_query_example() {
        let code = "db.query(\"SELECT * FROM users WHERE id = %s\", [user_id]);\n";
        assert!(check(Path::new("db.js"), code).is_empty());
    }
}
