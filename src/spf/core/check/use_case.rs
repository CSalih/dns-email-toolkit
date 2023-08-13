use crate::common::presenter::Presenter;
use crate::dns::core::dns_resolver::DnsResolver;
use crate::spf::core::check::checks::{check_lookup_count, check_max_txt_length, check_version};
use crate::spf::core::resolver::use_case::{ResolveSpfQuery, ResolveSpfUseCase};
use crate::spf::core::ResolveSpfUseCaseImpl;
use crate::spf::domain::{Term, Version};

pub trait SummarySpfUseCase {
    /// Summary the SPF record of a domain name.
    fn execute(
        &mut self,
        query: &SummarySpfQuery,
        presenter: Box<dyn Presenter<SpfSummary, String>>,
    );
}

pub struct SpfSummary {
    /// The version of the SPF record (e.g. "spf1")
    pub version: Version,

    /// The list of directives or modifiers
    pub terms: Vec<Term>,

    /// RDATA of a single DNS TXT resource record
    pub raw_rdata: String,
}

pub struct SummarySpfQuery {
    pub domain_name: String,
    pub record: Option<String>,
}

pub struct SummarySpfUseCaseImpl<'a> {
    spf_resolver: Box<dyn ResolveSpfUseCase + 'a>,
}

impl<'a> SummarySpfUseCaseImpl<'a> {
    pub fn new(dns_resolver: &'a mut dyn DnsResolver) -> Self {
        SummarySpfUseCaseImpl {
            spf_resolver: Box::new(ResolveSpfUseCaseImpl::new(dns_resolver)),
        }
    }
}

impl<'a> SummarySpfUseCase for SummarySpfUseCaseImpl<'a> {
    fn execute(
        &mut self,
        query: &SummarySpfQuery,
        mut presenter: Box<dyn Presenter<SpfSummary, String>>,
    ) {
        let spf_summary = self.spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: query.domain_name.to_owned(),
            record: query.record.to_owned(),
        });

        if spf_summary.is_err() {
            presenter.error(format!("No SPF record found for '{}'", query.domain_name));
            return;
        }
        let spf_summary = spf_summary.unwrap();

        // checks
        if let Err(err) = check_max_txt_length(&spf_summary.raw_rdata) {
            presenter.error(err.description);
            return;
        }

        if let Err(err) = check_version(&spf_summary.raw_rdata) {
            presenter.error(err.description);
            return;
        }

        if let Err(err) = check_lookup_count(&spf_summary.terms, &spf_summary.raw_rdata) {
            presenter.error(err.description);
            return;
        }

        presenter.success(SpfSummary {
            version: spf_summary.version,
            terms: spf_summary.terms,
            raw_rdata: spf_summary.raw_rdata,
        })
    }
}
