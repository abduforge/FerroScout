#![forbid(unsafe_code)]

use clap::Parser;
use ferroscout::cli::{Cli, Commands, OutputFormat, SeverityArg};
use ferroscout::models::Severity;
use ferroscout::report::{render_json, render_sarif, render_text};
use ferroscout::rules::rule_catalog;
use ferroscout::scanner::{filter_findings, scan_target, ScanOptions, MAX_ALLOWED_FILE_SIZE};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("ferroscout: {message}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<u8, String> {
    match cli.command {
        Some(Commands::Rules) => {
            println!("FerroScout security rules\n");
            for (id, description) in rule_catalog() {
                println!("{id:18} {description}");
            }
            Ok(0)
        }
        Some(Commands::Scan {
            path,
            format,
            severity,
            exclude,
            max_file_size,
        }) => {
            if max_file_size == 0 || max_file_size > MAX_ALLOWED_FILE_SIZE {
                return Err(format!(
                    "--max-file-size must be between 1 and {MAX_ALLOWED_FILE_SIZE} bytes"
                ));
            }
            let options = ScanOptions {
                excludes: exclude,
                max_file_size,
            };
            let mut report = scan_target(&path, &options)
                .map_err(|error| format!("cannot scan {}: {error}", path.display()))?;
            let minimum = severity.map(|value| match value {
                SeverityArg::Low => Severity::Low,
                SeverityArg::Medium => Severity::Medium,
                SeverityArg::High => Severity::High,
            });
            filter_findings(&mut report.findings, minimum);
            report.refresh_status();

            let rendered = match format {
                OutputFormat::Text => render_text(&report),
                OutputFormat::Json => render_json(&report)
                    .map_err(|error| format!("cannot serialize JSON report: {error}"))?,
                OutputFormat::Sarif => render_sarif(&report)
                    .map_err(|error| format!("cannot serialize SARIF report: {error}"))?,
            };
            println!("{rendered}");
            if !report.findings.is_empty() {
                Ok(1)
            } else if report.status == ferroscout::models::ScanStatus::InsufficientContext {
                Ok(2)
            } else {
                Ok(0)
            }
        }
        None => {
            println!("{}", Cli::command().render_help());
            Ok(0)
        }
    }
}

use clap::CommandFactory;
