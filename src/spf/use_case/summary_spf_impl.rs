use crate::common::presenter::Presenter;
use crate::spf::domain::model::{Term, Version};
use crate::spf::use_case::summary_spf::{SpfSummary, SummarySpfQuery, SummarySpfUseCase};
use crate::spf::use_case::summary_spf_gateway::{QueryTxtRecordGateway, QueryTxtRecordQuery};

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
            .filter(|line| line.starts_with("v=spf1")) // TODO: it must exactly match 'v=spf1' is not allowed
            .nth(0);

        if raw_rdata_option.is_none() {
            presenter.error(format!("No SPF record found for {}", query.domain_name));
            return;
        }
        let raw_rdata = raw_rdata_option.unwrap();
        let rdata_parts = raw_rdata.split(" ");

        let version = Version::from_str(rdata_parts.clone().next().unwrap());
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
