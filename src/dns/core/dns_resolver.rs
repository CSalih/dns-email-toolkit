use crate::dns::domain::{ARecord, TxtRecord};
use std::error::Error;

pub trait DnsResolver {
    /// Query the TXT record of a domain name.
    fn query_a(&mut self, query: &ARecordQuery) -> Result<ARecord, Box<dyn Error>>;

    /// Query the TXT record of a domain name.
    fn query_txt(&mut self, query: &TxtRecordQuery) -> Result<TxtRecord, Box<dyn Error>>;
}

pub struct ARecordQuery {
    pub domain_name: String,
}

pub struct TxtRecordQuery {
    pub domain_name: String,
}
