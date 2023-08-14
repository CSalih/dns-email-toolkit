use crate::common::presenter::Presenter;
use crate::dns::infrastructure::dns_resolver::DomainDnsResolver;
use crate::spf::core::check::{
    SpfSummary, SummarySpfQuery, SummarySpfTerminalPresenter, SummarySpfUseCase,
    SummarySpfUseCaseImpl, SummarySpfWithDetailTerminalPresenter,
};
use clap::Args;

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

pub fn spf_command(spf: &Spf) {
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
