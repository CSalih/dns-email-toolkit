use crate::common::presenter::Presenter;
use crate::spf::domain::model::{Term, Version};

pub trait SummarySpfUseCase {
    /// Summary the SPF record of a domain name.
    fn execute(
        &mut self,
        query: &SummarySpfQuery,
        presenter: &mut impl Presenter<SpfSummary, String>,
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
}
