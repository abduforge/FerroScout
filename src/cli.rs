use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "ferroscout",
    version,
    about = "A local, passive static security scanner with JSON and SARIF reports",
    long_about = "FerroScout inspects source and configuration files locally. It does not execute scanned code or contact remote systems. Findings are heuristic and require developer review. Reports are available as text, Markdown, JSON, or SARIF 2.1.0. You can filter noisy rules and suppress individual findings with documented source comments."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan a file or directory without modifying it.
    Scan {
        /// File or directory to inspect.
        path: PathBuf,
        /// Output format (text, markdown, json, or sarif).
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
        /// Show findings at this severity or higher.
        #[arg(long, value_enum)]
        severity: Option<SeverityArg>,
        /// Exclude a directory name or path (repeatable).
        #[arg(long = "exclude")]
        exclude: Vec<String>,
        /// Exclude findings from a specific rule (repeatable; use an ID from `ferroscout rules`).
        #[arg(long = "exclude-rule")]
        exclude_rule: Vec<String>,
        /// Skip files larger than this many bytes.
        #[arg(long, default_value_t = 2 * 1024 * 1024)]
        max_file_size: u64,
    },
    /// List the security checks included in this build.
    Rules,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    Markdown,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SeverityArg {
    Low,
    Medium,
    High,
}
