use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanStatus {
    FindingsFound,
    NoIssuesFound,
    InsufficientContext,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub file: String,
    pub line: usize,
    pub rule_id: String,
    pub cwe: Option<String>,
    pub confidence: Confidence,
    pub evidence: String,
    pub explanation: String,
    pub impact: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub tool: String,
    pub version: String,
    pub target: String,
    pub status: ScanStatus,
    pub files_scanned: usize,
    pub entries_skipped: usize,
    pub findings: Vec<Finding>,
    pub scan_errors: Vec<String>,
}

impl ScanReport {
    pub fn refresh_status(&mut self) {
        self.status = if !self.findings.is_empty() {
            ScanStatus::FindingsFound
        } else if self.files_scanned == 0 || !self.scan_errors.is_empty() {
            ScanStatus::InsufficientContext
        } else {
            ScanStatus::NoIssuesFound
        };
    }
}
