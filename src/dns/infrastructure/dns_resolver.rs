use crate::dns::core::dns_resolver::{ARecordQuery, DnsResolver, MxRecordQuery, TxtRecordQuery};
use crate::dns::domain::{ARecord, MxRecord, TxtRecord};
use domain::base::{Dname, Rtype};
use domain::rdata::{AllRecordData, Mx};
use domain::resolv::StubResolver;
use std::error::Error;
use std::str::FromStr;
use std::thread;

pub struct DomainDnsResolver {}

impl DomainDnsResolver {
    pub fn new() -> Self {
        DomainDnsResolver {}
    }
}

impl Default for DomainDnsResolver {
    fn default() -> Self {
        DomainDnsResolver::new()
    }
}

#[allow(clippy::needless_return)]
impl DnsResolver for DomainDnsResolver {
    fn query_a(&mut self, query: &ARecordQuery) -> Result<ARecord, Box<dyn Error>> {
        let domain_name = Dname::<Vec<_>>::from_str(&query.domain_name).unwrap();
        log::trace!(
            "Request dns question of type 'a record' for '{}'",
            domain_name
        );

        let res = thread::spawn(|| {
            return StubResolver::run(move |stub| async move {
                let res = stub.lookup_host(domain_name).await;

                match res {
                    Ok(answer) => {
                        let ip_addresses = answer.iter().collect::<Vec<_>>();
                        log::debug!("Got dns answer with {} records", ip_addresses.len());

                        Ok(ip_addresses)
                    }
                    Err(err) => Err(Box::new(err)),
                }
            });
        })
        .join()
        .expect("Thread panicked");

        match res {
            Ok(answer) => Ok(ARecord {
                ip_addresses: answer,
            }),
            Err(err) => Err(Box::new(err)),
        }
    }

    fn query_txt(&mut self, command: &TxtRecordQuery) -> Result<TxtRecord, Box<dyn Error>> {
        let domain_name = Dname::<Vec<_>>::from_str(&command.domain_name).unwrap();
        log::trace!(
            "Request dns question of type 'txt record' for '{}'",
            domain_name
        );

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

                log::debug!("Got dns answer with {} records", records.len());
                Ok(TxtRecord { records })
            }
            Err(err) => Err(Box::new(err)),
        }
    }

    fn query_mx(&mut self, query: &MxRecordQuery) -> Result<MxRecord, Box<dyn Error>> {
        let domain_name = Dname::<Vec<_>>::from_str(&query.domain_name).unwrap();
        log::trace!(
            "Request dns question of type 'mx record' for '{}'",
            domain_name
        );

        let res = thread::spawn(|| {
            return StubResolver::run(move |stub| async move {
                stub.query((domain_name, Rtype::Mx)).await
            });
        })
        .join()
        .expect("Thread panicked");

        match res {
            Ok(answer) => {
                let exchanges = answer
                    .answer()
                    .unwrap()
                    .limit_to::<Mx<_>>()
                    .map(|record| record.unwrap().data().exchange().to_string())
                    .collect::<Vec<String>>();

                log::debug!("Got dns answer with {} records", exchanges.len());
                Ok(MxRecord { exchanges })
            }
            Err(err) => Err(Box::new(err)),
        }
    }
}
