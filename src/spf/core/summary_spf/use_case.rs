use std::str::FromStr;

use crate::common::presenter::Presenter;
use crate::spf::core::summary_spf::gateway::{QueryTxtRecordGateway, QueryTxtRecordQuery};
use crate::spf::domain::{Term, Version};

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

pub struct SummarySpfUseCaseImpl<'a> {
    query_txt_record_gateway: &'a mut dyn QueryTxtRecordGateway,
}

impl<'a> SummarySpfUseCaseImpl<'a> {
    pub fn new(query_txt_record_gateway: &'a mut dyn QueryTxtRecordGateway) -> Self {
        SummarySpfUseCaseImpl {
            query_txt_record_gateway,
        }
    }
}

impl<'a> SummarySpfUseCase for SummarySpfUseCaseImpl<'a> {
    fn execute(
        &mut self,
        query: &SummarySpfQuery,
        presenter: &mut impl Presenter<SpfSummary, String>,
    ) {
        let result = self
            .query_txt_record_gateway
            .query_txt(&QueryTxtRecordQuery {
                domain_name: query.domain_name.clone(),
            })
            .expect("query txt record");

        // first is the version otherwise a term can be a mechanism or a modifier
        let raw_rdata_option = result
            .records
            .iter()
            .map(|record| record.to_string())
            .find(|line| line.starts_with("v=spf1")); // TODO: it must exactly match 'v=spf1' is not allowed

        if raw_rdata_option.is_none() {
            presenter.error(format!("No SPF record found for {}", query.domain_name));
            return;
        }
        let raw_rdata = raw_rdata_option.unwrap();
        let rdata_parts = raw_rdata.split(' ');

        let version = Version::from_str(rdata_parts.clone().next().unwrap()).unwrap();
        let terms = rdata_parts
            .clone()
            .skip(1)
            .map(|s| Term::from_str(s).unwrap())
            .collect::<Vec<_>>();

        presenter.success(SpfSummary {
            raw_rdata: rdata_parts.clone().collect::<Vec<&str>>().join(" "),
            version,
            terms,
        })
    }
}
