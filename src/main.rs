use clap::{Parser, Subcommand};

use crate::spf::infrastructure::{spf_command, Spf};

pub mod common;
pub mod dns;
pub mod spf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
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
async fn main() {
    let args = Cli::parse();

    match &args.command {
        Commands::Spf(spf) => spf_command(spf),
    }
}
