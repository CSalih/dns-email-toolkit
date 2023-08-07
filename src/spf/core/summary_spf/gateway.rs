use std::error::Error;

pub trait QueryTxtRecordGateway {
    /// Query the TXT record of a domain name.
    fn query_txt(&mut self, query: &QueryTxtRecordQuery) -> Result<QueryTxtRecord, Box<dyn Error>>;
}

pub struct QueryTxtRecord {
    pub records: Vec<String>, // TODO: this is a type of domain::base::rtype::Record
}

pub struct QueryTxtRecordQuery {
    pub domain_name: String,
}
