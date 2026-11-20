#![forbid(unsafe_code)]

use clap::Parser;
use ferroscout::baseline::{apply_baseline, build_baseline, load_baseline, save_baseline};
use ferroscout::cli::{BaselineCommands, Cli, Commands, OutputFormat, SeverityArg};
use ferroscout::models::Severity;
use ferroscout::report::{render_json, render_markdown, render_sarif, render_text};
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
            exclude_rule,
            baseline,
            max_file_size,
        }) => {
            if max_file_size == 0 || max_file_size > MAX_ALLOWED_FILE_SIZE {
                return Err(format!(
                    "--max-file-size must be between 1 and {MAX_ALLOWED_FILE_SIZE} bytes"
                ));
            }
            for rule in &exclude_rule {
                if !rule_catalog()
                    .iter()
                    .any(|(known, _)| *known == rule.as_str())
                {
                    return Err(format!(
                        "unknown rule ID '{rule}'. Run 'ferroscout rules' to list valid IDs."
                    ));
                }
            }
            let options = ScanOptions {
                excludes: exclude,
                max_file_size,
            };
            let mut report = scan_target(&path, &options)
                .map_err(|error| format!("cannot scan {}: {error}", path.display()))?;
            if let Some(baseline_path) = baseline.as_deref() {
                let baseline_data = load_baseline(baseline_path)?;
                apply_baseline(&mut report, &baseline_data, &path)?;
            }
            let minimum = severity.map(|value| match value {
                SeverityArg::Low => Severity::Low,
                SeverityArg::Medium => Severity::Medium,
                SeverityArg::High => Severity::High,
            });
            report.filtered_findings +=
                filter_findings(&mut report.findings, minimum, &exclude_rule);
            report.refresh_status();

            let rendered = match format {
                OutputFormat::Text => render_text(&report),
                OutputFormat::Json => render_json(&report)
                    .map_err(|error| format!("cannot serialize JSON report: {error}"))?,
                OutputFormat::Sarif => render_sarif(&report)
                    .map_err(|error| format!("cannot serialize SARIF report: {error}"))?,
                OutputFormat::Markdown => render_markdown(&report),
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
        Some(Commands::Baseline {
            command:
                BaselineCommands::Create {
                    path,
                    output,
                    force,
                    exclude,
                    max_file_size,
                },
        }) => {
            if max_file_size == 0 || max_file_size > MAX_ALLOWED_FILE_SIZE {
                return Err(format!(
                    "--max-file-size must be between 1 and {MAX_ALLOWED_FILE_SIZE} bytes"
                ));
            }
            if output.exists() && !force {
                return Err(format!(
                    "baseline {} already exists; pass --force only after reviewing the new findings",
                    output.display()
                ));
            }
            let options = ScanOptions {
                excludes: exclude,
                max_file_size,
            };
            let report = scan_target(&path, &options)
                .map_err(|error| format!("cannot scan {}: {error}", path.display()))?;
            if report.files_scanned == 0 || !report.scan_errors.is_empty() {
                return Err(format!(
                    "refusing to create a baseline from an incomplete scan ({} files scanned, {} scan warnings/errors)",
                    report.files_scanned, report.scan_errors.len()
                ));
            }
            let baseline = build_baseline(&report, &path);
            save_baseline(&output, &baseline)?;
            println!(
                "Baseline created: {}\nRecorded findings: {}\nThe baseline stores fingerprints and redacted metadata, not source evidence.",
                output.display(), report.findings.len()
            );
            Ok(0)
        }
        None => {
            println!("{}", Cli::command().render_help());
            Ok(0)
        }
    }
}

use clap::CommandFactory;
