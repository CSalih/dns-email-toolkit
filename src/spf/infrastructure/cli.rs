use std::error::Error;

use clap::Args;

use crate::spf::domain::SpfError;
use crate::{
    common::{cli::CliCommand, presenter::Presenter},
    dns::infrastructure::dns_resolver::DomainDnsResolver,
    spf::core::check::{
        SpfSummary, SummarySpfQuery, SummarySpfTerminalPresenter, SummarySpfUseCase,
        SummarySpfUseCaseImpl, SummarySpfWithDetailTerminalPresenter,
    },
};

#[derive(Args)]
pub struct Spf {
    /// Output with details
    #[arg(short, long)]
    pub detail: bool,

    /// Use record value instead of querying it from DNS
    /// (useful for testing)
    #[arg(short, long)]
    pub record: Option<String>,

    /// Domain name to check
    pub domain: String,
}

impl CliCommand<Spf> for Spf {
    fn execute(&self) -> Result<(), Box<dyn Error>> {
        let mut dns_resolver_gateway = DomainDnsResolver::new();
        let presenter: Box<dyn Presenter<SpfSummary, SpfError>> = if self.detail {
            Box::new(SummarySpfWithDetailTerminalPresenter::new())
        } else {
            Box::new(SummarySpfTerminalPresenter::new())
        };
        let mut summary_spf_use_case = SummarySpfUseCaseImpl::new(&mut dns_resolver_gateway);

        let query = SummarySpfQuery {
            domain_name: self.domain.to_owned(),
            record: self.record.to_owned(),
        };
        summary_spf_use_case.execute(&query, presenter);

        Ok(())
    }
}
