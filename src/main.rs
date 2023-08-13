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
