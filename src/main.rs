use clap::{Parser, Subcommand};

use crate::spf::infrastructure::cli::Spf;
use crate::spf::infrastructure::gateway::DnsResolver;
use crate::spf::use_case::summary_spf::{SummarySpfQuery, SummarySpfUseCase};
use crate::spf::use_case::summary_spf_impl::SummarySpfUseCaseImpl;
use crate::spf::use_case::summary_spf_terminal_presenter::SummarySpfTerminalPresenter;

pub mod common;
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
            let mut dns_resolver_gateway = DnsResolver::new();
            let mut summary_spf_use_case = SummarySpfUseCaseImpl::new(&mut dns_resolver_gateway);
            let query = SummarySpfQuery {
                domain_name: spf.domain.clone(),
            };
            let mut presenter = SummarySpfTerminalPresenter::new();

            summary_spf_use_case.execute(&query, &mut presenter);
        }
    }
}
