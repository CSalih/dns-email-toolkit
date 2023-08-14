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

use crate::common::presenter::Presenter;
use crate::dns::infrastructure::dns_resolver::DomainDnsResolver;
use clap::{Parser, Subcommand};

use crate::spf::core::check::{
    SpfSummary, SummarySpfQuery, SummarySpfTerminalPresenter, SummarySpfUseCase,
    SummarySpfUseCaseImpl, SummarySpfWithDetailTerminalPresenter,
};
use crate::spf::infrastructure::cli::Spf;

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
        Commands::Spf(spf) => {
            let mut dns_resolver_gateway = DomainDnsResolver::new();
            let presenter: Box<dyn Presenter<SpfSummary, String>> = if spf.detail {
                Box::new(SummarySpfWithDetailTerminalPresenter::new())
            } else {
                Box::new(SummarySpfTerminalPresenter::new())
            };
            let mut summary_spf_use_case = SummarySpfUseCaseImpl::new(&mut dns_resolver_gateway);

            let query = SummarySpfQuery {
                domain_name: spf.domain.to_owned(),
                record: spf.record.to_owned(),
            };
            summary_spf_use_case.execute(&query, presenter);
        }
    }
}
