use std::str::FromStr;

use crate::dns::core::dns_resolver::{ARecordQuery, DnsResolver, MxRecordQuery, TxtRecordQuery};
use crate::spf::domain::{
    AMechanism, AllMechanism, Directive, IncludeMechanism, Ip4Mechanism, Ip6Mechanism, Mechanism,
    Modifier, MxMechanism, QualifierType, RedirectModifier, SpfError, Term, Version,
};

pub trait ResolveSpfUseCase {
    fn resolve(&mut self, query: &ResolveSpfQuery) -> Result<SpfAnswer, Box<SpfError>>;
}

pub struct ResolveSpfQuery {
    /// The domain name to query
    pub domain_name: String,

    /// The SPF record to parse. If not provided, the record will be fetched from DNS.
    pub record: Option<String>,
}

pub struct SpfAnswer {
    /// The version of the SPF record (e.g. "spf1")
    pub version: Version,

    /// The list of directives or modifiers
    pub terms: Vec<Term>,

    /// RDATA of a single DNS TXT resource record
    pub raw_rdata: String,
}

pub struct ResolveSpfUseCaseImpl<'a> {
    pub(crate) dns_resolver: &'a mut dyn DnsResolver,
}

impl<'a> ResolveSpfUseCaseImpl<'a> {
    pub fn new(query_txt_record_gateway: &'a mut dyn DnsResolver) -> Self {
        ResolveSpfUseCaseImpl {
            dns_resolver: query_txt_record_gateway,
        }
    }
}

impl<'a> ResolveSpfUseCase for ResolveSpfUseCaseImpl<'a> {
    fn resolve(&mut self, query: &ResolveSpfQuery) -> Result<SpfAnswer, Box<SpfError>> {
        let spf_rdata = match &query.record {
            Some(rdata) => Some(rdata.clone()),
            None => {
                let result = self
                    .dns_resolver
                    .query_txt(&TxtRecordQuery {
                        domain_name: query.domain_name.clone(),
                    })
                    .expect("query txt record");

                result
                    .records
                    .iter()
                    .map(|record| record.to_string())
                    .find(|line| line.starts_with("v=spf1"))
            }
        };

        if spf_rdata.is_none() {
            return Err(Box::new(SpfError::NoSpfRecordFound(format!(
                "No SPF record found for '{}'",
                query.domain_name
            ))));
        }

        let raw_rdata = spf_rdata.unwrap();
        let mut rdata_parts = raw_rdata.split(' ');

        let version = Version::from_str(rdata_parts.next().unwrap()).unwrap();
        let terms = rdata_parts
            .map(|term| {
                let (qualifier, mechanism_str) = if term.starts_with(QualifierType::Pass.as_str()) {
                    (Some(QualifierType::Pass), &term[1..])
                } else if term.starts_with(QualifierType::Fail.as_str()) {
                    (Some(QualifierType::Fail), &term[1..])
                } else if term.starts_with(QualifierType::SoftFail.as_str()) {
                    (Some(QualifierType::SoftFail), &term[1..])
                } else if term.starts_with(QualifierType::Neutral.as_str()) {
                    (Some(QualifierType::Neutral), &term[1..])
                } else {
                    (None, term)
                };

                match mechanism_str {
                    mechanism_str if mechanism_str.starts_with("include:") => {
                        self.to_include_term_mut(qualifier, mechanism_str)
                    }
                    mechanism_str if mechanism_str == "a" || mechanism_str.starts_with("a:") => {
                        self.to_a_term_mut(
                            qualifier,
                            mechanism_str,
                            query.domain_name.clone().as_str(),
                        )
                    }
                    mechanism_str if mechanism_str == "mx" || mechanism_str.starts_with("mx:") => {
                        self.to_mx_term_mut(
                            qualifier,
                            mechanism_str,
                            query.domain_name.clone().as_str(),
                        )
                    }
                    mechanism_str if mechanism_str.starts_with("ip4:") => {
                        self.to_ipv4_term(qualifier, mechanism_str)
                    }
                    mechanism_str if mechanism_str.starts_with("ip6:") => {
                        self.to_ipv6_term(qualifier, mechanism_str)
                    }
                    mechanism_str if mechanism_str == "all" => {
                        self.to_all(qualifier, mechanism_str)
                    }
                    mechanism_str if mechanism_str.starts_with("redirect=") => {
                        self.to_redirect_term_mut(mechanism_str)
                    }
                    _ => Term::new_unknown(term, None),
                }
            })
            .collect::<Vec<_>>();

        Ok(SpfAnswer {
            raw_rdata,
            version,
            terms,
        })
    }
}

impl<'a> ResolveSpfUseCaseImpl<'a> {
    fn to_a_term_mut(
        &mut self,
        qualifier: Option<QualifierType>,
        term: &str,
        domain_name: &str,
    ) -> Term {
        let (_, domain_name) = term.split_once(':').unwrap_or((term, domain_name));
        let (domain_name, subnet_mask) = domain_name.split_once('/').unwrap_or((domain_name, ""));

        let a_record = self.dns_resolver.query_a(&ARecordQuery {
            domain_name: domain_name.to_string(),
        });
        let record = a_record.unwrap();

        Term::Directive(Directive {
            qualifier,
            mechanism: Mechanism::A(AMechanism {
                raw_value: term.to_string(),
                ip_addresses: record.ip_addresses,
                subnet_mask: subnet_mask.parse().ok(),
            }),
        })
    }

    fn to_mx_term_mut(
        &mut self,
        qualifier: Option<QualifierType>,
        term: &str,
        domain_name: &str,
    ) -> Term {
        let (_, domain_name) = term.split_once(':').unwrap_or((term, domain_name));
        let (domain_name, subnet_mask) = domain_name.split_once('/').unwrap_or((domain_name, ""));

        let a_record = self.dns_resolver.query_mx(&MxRecordQuery {
            domain_name: domain_name.to_string(),
        });
        let record = a_record.unwrap();

        Term::Directive(Directive {
            qualifier,
            mechanism: Mechanism::Mx(MxMechanism {
                raw_value: term.to_string(),
                hosts: record.exchanges,
                subnet_mask: subnet_mask.parse().ok(),
            }),
        })
    }

    fn to_include_term_mut(&mut self, qualifier: Option<QualifierType>, term: &str) -> Term {
        let (_, sub_domain_name) = term.split_once(':').unwrap_or((term, ""));

        let spf_summary = self.resolve(&ResolveSpfQuery {
            domain_name: sub_domain_name.to_string(),
            record: None,
        });

        match spf_summary {
            Err(err) => match err.as_ref() {
                SpfError::NoSpfRecordFound(err) => Term::new_unknown(term, Some(err.to_string())),
                _ => unreachable!(),
            },
            Ok(spf) => Term::Directive(Directive {
                qualifier,
                mechanism: Mechanism::Include(IncludeMechanism {
                    raw_value: term.to_string(),
                    version: spf.version,
                    domain_spec: sub_domain_name.to_string(),
                    terms: spf.terms,
                    raw_rdata: spf.raw_rdata,
                }),
            }),
        }
    }

    fn to_redirect_term_mut(&mut self, term: &str) -> Term {
        let (_, domain_name) = term.split_once('=').unwrap_or((term, ""));

        let spf_summary = self.resolve(&ResolveSpfQuery {
            domain_name: domain_name.to_string(),
            record: None,
        });

        match spf_summary {
            Err(err) => match err.as_ref() {
                SpfError::NoSpfRecordFound(err) => Term::new_unknown(term, Some(err.to_string())),
                _ => unreachable!(),
            },
            Ok(spf) => Term::Modifier(Modifier::Redirect(RedirectModifier {
                raw_value: term.to_string(),
                version: spf.version,
                domain_spec: domain_name.to_string(),
                terms: spf.terms,
                raw_rdata: spf.raw_rdata,
            })),
        }
    }

    fn to_ipv4_term(&self, qualifier: Option<QualifierType>, term: &str) -> Term {
        let (_, ip_address) = term.split_once(':').unwrap_or((term, ""));
        let (ip_address, subnet_mask) = ip_address.split_once('/').unwrap_or((ip_address, ""));

        Term::Directive(Directive {
            qualifier,
            mechanism: Mechanism::Ip4(Ip4Mechanism {
                raw_value: term.to_string(),
                ip_address: ip_address.parse().expect("IPv4 address"),
                subnet_mask: subnet_mask.parse().ok(),
            }),
        })
    }
    fn to_ipv6_term(&self, qualifier: Option<QualifierType>, term: &str) -> Term {
        let (_, ip_address) = term.split_once(':').unwrap_or((term, ""));
        let (ip_address, subnet_mask) = ip_address.split_once('/').unwrap_or((ip_address, ""));

        Term::Directive(Directive {
            qualifier,
            mechanism: Mechanism::Ip6(Ip6Mechanism {
                raw_value: term.to_string(),
                ip_address: ip_address.parse().expect("IPv6 address"),
                subnet_mask: subnet_mask.parse().ok(),
            }),
        })
    }
    fn to_all(&self, qualifier: Option<QualifierType>, term: &str) -> Term {
        Term::Directive(Directive {
            qualifier,
            mechanism: Mechanism::All(AllMechanism {
                raw_value: term.to_string(),
            }),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mockall::mock;

    use crate::dns::core::dns_resolver::{
        ARecordQuery, DnsResolver, MxRecordQuery, TxtRecordQuery,
    };
    use crate::dns::domain::{ARecord, MxRecord, TxtRecord};
    use crate::spf::domain::Term;
    use std::error::Error;
    use std::net::IpAddr;

    mock! {
        pub DnsResolver {}

        impl DnsResolver for DnsResolver {
            fn query_a(&mut self, query: &ARecordQuery) -> Result<ARecord, Box<dyn Error>>;
            fn query_txt(&mut self, query: &TxtRecordQuery) -> Result<TxtRecord, Box<dyn Error>>;
            fn query_mx(&mut self, query: &MxRecordQuery) -> Result<MxRecord, Box<dyn Error>>;
        }
    }

    #[test]
    fn it_should_return_no_spf_record_found() {
        // Arrange
        let mut dns_resolver = MockDnsResolver::new();
        dns_resolver
            .expect_query_txt()
            .once()
            .return_once(move |_| Ok(TxtRecord { records: vec![] }));
        let mut spf_resolver = ResolveSpfUseCaseImpl::new(&mut dns_resolver);

        // Act
        let spf_summary = spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: "example.com".to_owned(),
            record: None,
        });

        // Assert
        dns_resolver.checkpoint();
        assert!(
            spf_summary.is_err(),
            "No error was not returned but expected"
        );
        match *spf_summary.err().unwrap() {
            SpfError::NoSpfRecordFound(_) => {}
            _ => panic!("Expected NoSpfRecordFound error but was not returned"),
        }
    }

    #[test]
    fn it_should_return_a_spf_record() {
        // Arrange
        let mut dns_resolver = MockDnsResolver::new();
        dns_resolver
            .expect_query_txt()
            .once()
            .return_once(move |_| {
                Ok(TxtRecord {
                    records: vec!["v=spf1".to_owned()],
                })
            });
        let mut spf_resolver = ResolveSpfUseCaseImpl::new(&mut dns_resolver);

        // Act
        let spf_summary = spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: "example.com".to_owned(),
            record: None,
        });

        // Assert
        dns_resolver.checkpoint();
        assert!(
            spf_summary.is_ok(),
            "SPF Answer was expected but not returned"
        );
    }

    #[test]
    fn it_should_use_the_record_from_query() {
        // Arrange
        let mut dns_resolver = MockDnsResolver::new();
        dns_resolver.expect_query_txt().never();
        let mut spf_resolver = ResolveSpfUseCaseImpl::new(&mut dns_resolver);

        // Act
        let spf_summary = spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: "example.com".to_owned(),
            record: Some("v=spf1 -all".to_owned()),
        });

        // Assert
        dns_resolver.checkpoint();
        assert!(
            spf_summary.is_ok(),
            "SPF Answer was expected but not returned"
        );
    }

    #[test]
    fn it_should_be_a_valid_spf_version() {
        // Arrange
        let mut dns_resolver = MockDnsResolver::new();
        dns_resolver
            .expect_query_txt()
            .once()
            .return_once(move |_| {
                Ok(TxtRecord {
                    records: vec!["v=spf1 -all".to_owned()],
                })
            });
        let mut spf_resolver = ResolveSpfUseCaseImpl::new(&mut dns_resolver);

        // Act
        let spf_summary = spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: "example.com".to_owned(),
            record: None,
        });

        // Assert
        dns_resolver.checkpoint();
        let actual_version_str = spf_summary.unwrap().version.version;
        let expected_version_str = "v=spf1";

        assert_eq!(actual_version_str, expected_version_str);
    }

    #[test]
    fn it_should_be_a_valid_include_mechanism() {
        // Arrange
        let mut dns_resolver = MockDnsResolver::new();
        dns_resolver
            .expect_query_txt()
            .times(2)
            .returning(move |query| {
                if query.domain_name == "example.com" {
                    Ok(TxtRecord {
                        records: vec!["v=spf1 include:_spf.example.com".to_owned()],
                    })
                } else {
                    Ok(TxtRecord {
                        records: vec!["v=spf1 -all".to_owned()],
                    })
                }
            });
        let mut spf_resolver = ResolveSpfUseCaseImpl::new(&mut dns_resolver);

        // Act
        let spf_summary = spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: "example.com".to_owned(),
            record: None,
        });

        // Assert
        dns_resolver.checkpoint();
        let actual_spf_answer = spf_summary.unwrap();

        assert_eq!(actual_spf_answer.terms.len(), 1);
        assert!(matches!(
            actual_spf_answer.terms.first().unwrap(),
            Term::Directive(e) if matches!(e.mechanism, Mechanism::Include(_))
        ));
    }

    #[test]
    fn it_should_be_a_valid_a_mechanism() {
        // Arrange
        let mut dns_resolver = MockDnsResolver::new();
        dns_resolver
            .expect_query_txt()
            .once()
            .return_once(move |_| {
                Ok(TxtRecord {
                    records: vec!["v=spf1 a".to_owned()],
                })
            });
        dns_resolver.expect_query_a().once().return_once(move |_| {
            Ok(ARecord {
                ip_addresses: vec![IpAddr::from_str("127.0.0.1").unwrap()],
            })
        });
        let mut spf_resolver = ResolveSpfUseCaseImpl::new(&mut dns_resolver);

        // Act
        let spf_summary = spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: "example.com".to_owned(),
            record: None,
        });

        // Assert
        dns_resolver.checkpoint();
        let actual_spf_answer = spf_summary.unwrap();

        assert_eq!(actual_spf_answer.terms.len(), 1);
        assert!(matches!(
            actual_spf_answer.terms.first().unwrap(),
            Term::Directive(e) if matches!(e.mechanism, Mechanism::A(_))
        ));
    }

    #[test]
    fn it_should_be_a_valid_mx_mechanism() {
        // Arrange
        let mut dns_resolver = MockDnsResolver::new();
        dns_resolver
            .expect_query_txt()
            .once()
            .return_once(move |_| {
                Ok(TxtRecord {
                    records: vec!["v=spf1 mx".to_owned()],
                })
            });
        dns_resolver.expect_query_mx().once().return_once(move |_| {
            Ok(MxRecord {
                exchanges: vec!["example.com".to_owned()],
            })
        });
        let mut spf_resolver = ResolveSpfUseCaseImpl::new(&mut dns_resolver);

        // Act
        let spf_summary = spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: "example.com".to_owned(),
            record: None,
        });

        // Assert
        dns_resolver.checkpoint();
        let actual_spf_answer = spf_summary.unwrap();

        assert_eq!(actual_spf_answer.terms.len(), 1);
        assert!(matches!(
            actual_spf_answer.terms.first().unwrap(),
            Term::Directive(e) if matches!(e.mechanism, Mechanism::Mx(_))
        ));
    }

    #[test]
    fn it_should_be_a_valid_ip4_mechanism() {
        // Arrange
        let mut dns_resolver = MockDnsResolver::new();
        dns_resolver
            .expect_query_txt()
            .once()
            .return_once(move |_| {
                Ok(TxtRecord {
                    records: vec!["v=spf1 ip4:127.0.0.1".to_owned()],
                })
            });
        let mut spf_resolver = ResolveSpfUseCaseImpl::new(&mut dns_resolver);

        // Act
        let spf_summary = spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: "example.com".to_owned(),
            record: None,
        });

        // Assert
        dns_resolver.checkpoint();
        let actual_spf_answer = spf_summary.unwrap();

        assert_eq!(actual_spf_answer.terms.len(), 1);
        assert!(matches!(
            actual_spf_answer.terms.first().unwrap(),
            Term::Directive(e) if matches!(e.mechanism, Mechanism::Ip4(_))
        ));
    }

    #[test]
    fn it_should_be_a_valid_ip6_mechanism() {
        // Arrange
        let mut dns_resolver = MockDnsResolver::new();
        dns_resolver
            .expect_query_txt()
            .once()
            .return_once(move |_| {
                Ok(TxtRecord {
                    records: vec!["v=spf1 ip6:::1".to_owned()],
                })
            });
        let mut spf_resolver = ResolveSpfUseCaseImpl::new(&mut dns_resolver);

        // Act
        let spf_summary = spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: "example.com".to_owned(),
            record: None,
        });

        // Assert
        dns_resolver.checkpoint();
        let actual_spf_answer = spf_summary.unwrap();

        assert_eq!(actual_spf_answer.terms.len(), 1);
        assert!(matches!(
            actual_spf_answer.terms.first().unwrap(),
            Term::Directive(e) if matches!(e.mechanism, Mechanism::Ip6(_))
        ));
    }

    #[test]
    fn it_should_be_a_valid_all_mechanism() {
        // Arrange
        let mut dns_resolver = MockDnsResolver::new();
        dns_resolver
            .expect_query_txt()
            .once()
            .return_once(move |_| {
                Ok(TxtRecord {
                    records: vec!["v=spf1 all".to_owned()],
                })
            });
        let mut spf_resolver = ResolveSpfUseCaseImpl::new(&mut dns_resolver);

        // Act
        let spf_summary = spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: "example.com".to_owned(),
            record: None,
        });

        // Assert
        dns_resolver.checkpoint();
        let actual_spf_answer = spf_summary.unwrap();

        assert_eq!(actual_spf_answer.terms.len(), 1);
        assert!(matches!(
            actual_spf_answer.terms.first().unwrap(),
            Term::Directive(e) if matches!(e.mechanism, Mechanism::All(_))
        ));
    }

    #[test]
    fn it_should_be_a_valid_redirect_mechanism() {
        // Arrange
        let mut dns_resolver = MockDnsResolver::new();
        dns_resolver
            .expect_query_txt()
            .times(2)
            .returning(move |query| {
                if query.domain_name == "example.com" {
                    Ok(TxtRecord {
                        records: vec!["v=spf1 redirect=_spf.example.com".to_owned()],
                    })
                } else {
                    Ok(TxtRecord {
                        records: vec!["v=spf1 -all".to_owned()],
                    })
                }
            });
        let mut spf_resolver = ResolveSpfUseCaseImpl::new(&mut dns_resolver);

        // Act
        let spf_summary = spf_resolver.resolve(&ResolveSpfQuery {
            domain_name: "example.com".to_owned(),
            record: None,
        });

        // Assert
        dns_resolver.checkpoint();
        let actual_spf_answer = spf_summary.unwrap();

        assert_eq!(actual_spf_answer.terms.len(), 1);
        assert!(matches!(
            actual_spf_answer.terms.first().unwrap(),
            Term::Modifier(e) if matches!(e, Modifier::Redirect(_))
        ));
    }
}
