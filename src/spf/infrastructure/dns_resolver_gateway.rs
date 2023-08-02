use std::error::Error;
use std::str::FromStr;
use std::thread;

use crate::spf::use_case::summary_spf_gateway::{
    QueryTxtRecord, QueryTxtRecordGateway, QueryTxtRecordQuery,
};
use domain::base::{Dname, Rtype};
use domain::rdata::AllRecordData;
use domain::resolv::StubResolver;

pub struct DnsResolverGateway {}

impl DnsResolverGateway {
    pub fn new() -> Self {
        DnsResolverGateway {}
    }
}

impl QueryTxtRecordGateway for DnsResolverGateway {
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
                    .map(|record| record.unwrap().data().to_string())
                    .collect::<Vec<String>>();

                println!("[Info] Found {} TXT records", records.iter().count());
                Ok(QueryTxtRecord { records })
            }
            Err(err) => Err(Box::new(err)),
        }
    }
}
