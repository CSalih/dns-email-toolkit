use std::str::FromStr;

use crate::dns::core::dns_resolver::{ARecordQuery, DnsResolver, MxRecordQuery, TxtRecordQuery};
use crate::spf::domain::{
    AMechanism, AllMechanism, Directive, IncludeMechanism, Ip4Mechanism, Ip6Mechanism, Mechanism,
    MxMechanism, QualifierType, SpfError, Term, UnknownTerm, Version,
};

pub trait ResolveSpfUseCase {
    fn resolve(&mut self, query: &ResolveSpfQuery) -> Result<SpfAnswer, SpfError>;
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
    fn resolve(&mut self, query: &ResolveSpfQuery) -> Result<SpfAnswer, SpfError> {
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
            return Err(SpfError::NoSpfRecordFound);
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
                    _ => Term::Unknown(UnknownTerm {
                        raw_rdata: term.to_string(),
                    }),
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
            Err(_) => Term::Unknown(UnknownTerm {
                raw_rdata: "No spf found".to_string(),
            }),
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
