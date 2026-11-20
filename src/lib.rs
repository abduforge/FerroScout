#![forbid(unsafe_code)]

pub mod baseline;
pub mod cli;
pub mod models;
pub mod report;
pub mod rules;
pub mod scanner;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
