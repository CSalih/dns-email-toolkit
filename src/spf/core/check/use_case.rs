use crate::common::presenter::Presenter;
use crate::dns::core::dns_resolver::DnsResolver;
use crate::spf::core::check::checks::{check_lookup_count, check_max_txt_length, check_version};
use crate::spf::core::resolver::use_case::{ResolveSpfQuery, ResolveSpfUseCase};
use crate::spf::core::ResolveSpfUseCaseImpl;
use crate::spf::domain::{SpfError, Term, Version};

pub trait SummarySpfUseCase {
    /// Summary the SPF record of a domain name.
    fn execute(
        &mut self,
        query: &SummarySpfQuery,
        presenter: Box<dyn Presenter<SpfSummary, SpfError>>,
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
        mut presenter: Box<dyn Presenter<SpfSummary, SpfError>>,
    ) {
        let spf_summary = self.spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: query.domain_name.to_owned(),
            record: query.record.to_owned(),
        });

        let Ok(spf_summary) = spf_summary else {
            if let Some(err) = spf_summary.err() {
                presenter.error(&err);
            }
            return;
        };

        // checks
        let mut check_errors: Vec<SpfError> = vec![];
        if let Err(err) = check_max_txt_length(&spf_summary.raw_rdata) {
            check_errors.push(err.into());
        }
        if let Err(err) = check_version(&spf_summary.raw_rdata) {
            check_errors.push(err.into());
        }
        if let Err(err) = check_lookup_count(&spf_summary.terms, &spf_summary.raw_rdata) {
            check_errors.push(err.into());
        }

        if check_errors.is_empty() {
            presenter.success(&SpfSummary {
                version: spf_summary.version,
                terms: spf_summary.terms,
                raw_rdata: spf_summary.raw_rdata,
            });
        } else {
            check_errors.iter().for_each(|err| {
                presenter.error(err);
            });
        }
    }
}
