use crate::dns::core::dns_resolver::{ARecordQuery, DnsResolver, TxtRecordQuery};
use crate::dns::domain::{ARecord, TxtRecord};
use domain::base::{Dname, Rtype};
use domain::rdata::AllRecordData;
use domain::resolv::StubResolver;
use std::error::Error;
use std::net::IpAddr;
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
        println!("[Debug] Try collecting a records for '{}'", domain_name);

        let res = thread::spawn(|| {
            return StubResolver::run(move |stub| async move {
                let res = stub.lookup_host(domain_name).await;

                match res {
                    Ok(answer) => {
                        let canon = answer.canonical_name();
                        if canon != answer.qname() {
                            println!("{} is an alias for {}", answer.qname(), canon);
                        }

                        let ip_addresses = answer
                            .iter()
                            .map(|addr| match addr {
                                IpAddr::V4(ip) => ip,
                                IpAddr::V6(_) => {
                                    panic!("DNS resolver for a records does not support IPv6")
                                }
                            })
                            .collect::<Vec<_>>();
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
                Ok(TxtRecord { records })
            }
            Err(err) => Err(Box::new(err)),
        }
    }
}
