//! `det` is a command line tool for email related DNS records.
//!
//! You can use `det` to check the following DNS records:
//! - [Sender Policy Framework (SPF)](https://datatracker.ietf.org/doc/html/rfc7208)
//!
//! # Usage
//!
//! Check the SPF record for a domain
//! ```bash
//! det spf example.com
//! ```
//!
//! you can provide a specific SPF record to check
//!
//! ```bash
//! det spf example.com --record "v=spf1 -all"
//! ```
//!
//! you can also get more details about the SPF record
//!
//! ```bash
//! det spf example.com --detail
//! ```

use std::env;
use std::error::Error;

use clap::{Parser, Subcommand};
use common::cli::CliCommand;

use crate::spf::infrastructure::cli::Spf;

pub mod common;
pub mod dns;
pub mod spf;

#[derive(Parser)]
#[command(
    author,
    version = env!("DET_VERSION_FULL"),
    long_about = None
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sender Policy Framework (SPF) utility
    Spf(Spf),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    match &args.command {
        Commands::Spf(spf) => spf.execute(),
    }
}
