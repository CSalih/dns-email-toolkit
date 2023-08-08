use crate::spf::core::summary_spf::gateway::{
    QueryTxtRecord, QueryTxtRecordGateway, QueryTxtRecordQuery,
};
use domain::base::{Dname, Rtype};
use domain::rdata::AllRecordData;
use domain::resolv::StubResolver;
use std::error::Error;
use std::str::FromStr;
use std::thread;

pub struct InMemoryDnsResolver {
    rdata: String,
}

impl InMemoryDnsResolver {
    pub fn new(rdata: String) -> Self {
        InMemoryDnsResolver { rdata }
    }
}

impl QueryTxtRecordGateway for InMemoryDnsResolver {
    fn query_txt(&mut self, query: &QueryTxtRecordQuery) -> Result<QueryTxtRecord, Box<dyn Error>> {
        println!(
            "[Debug] Try collecting TXT record for '{}' using in-memory dns resolver",
            query.domain_name
        );

        let records = vec![self.rdata.clone()];

        println!("[Info] Found {} TXT records", records.len());
        Ok(QueryTxtRecord { records })
    }
}

pub struct DnsResolver {}

impl DnsResolver {
    pub fn new() -> Self {
        DnsResolver {}
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        DnsResolver::new()
    }
}

impl QueryTxtRecordGateway for DnsResolver {
    fn query_txt(
        &mut self,
        command: &QueryTxtRecordQuery,
    ) -> Result<QueryTxtRecord, Box<dyn Error>> {
        let domain_name = Dname::<Vec<_>>::from_str(&command.domain_name).unwrap();
        println!("[Debug] Try collecting TXT records for '{}'", domain_name);

        let res = thread::spawn(|| {
            return StubResolver::run(move |stub| async move {
                stub.query((domain_name, Rtype::Txt)).await
            });
        })
        .join()
        .expect("Thread panicked");

        match res {
            Ok(answer) => {
                let records = answer
                    .answer()
                    .unwrap()
                    .limit_to::<AllRecordData<_, _>>()
                    .map(|record| record.unwrap().data().to_string().replace("\\32", " "))
                    .collect::<Vec<String>>();

                println!("[Info] Found {} TXT records", records.len());
                Ok(QueryTxtRecord { records })
            }
            Err(err) => Err(Box::new(err)),
        }
    }
}
