use clap::{Parser, Subcommand};

use crate::spf::core::summary_spf::{
    QueryTxtRecordGateway, SummarySpfQuery, SummarySpfTerminalPresenter, SummarySpfUseCase,
    SummarySpfUseCaseImpl,
};
use crate::spf::infrastructure::cli::Spf;
use crate::spf::infrastructure::gateway::{DnsResolver, InMemoryDnsResolver};

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
            let mut dns_resolver_gateway: Box<dyn QueryTxtRecordGateway> = match &spf.record {
                None => Box::new(DnsResolver::new()),
                Some(rdata) => Box::new(InMemoryDnsResolver::new(rdata.to_string())),
            };
            let mut summary_spf_use_case = SummarySpfUseCaseImpl::new(&mut *dns_resolver_gateway);
            let mut presenter = SummarySpfTerminalPresenter::new();

            let query = SummarySpfQuery {
                domain_name: spf.domain.clone(),
            };
            summary_spf_use_case.execute(&query, &mut presenter);
        }
    }
}
