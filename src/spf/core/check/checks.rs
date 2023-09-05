use crate::spf::domain::{CheckError, Mechanism, Modifier, Term, UnknownTerm};

/// Records that are too long to fit in a single UDP packet
/// MAY be silently ignored by SPF clients.
pub fn check_max_txt_length(rdata: &str) -> Result<(), CheckError> {
    const MAX_TXT_LENGTH: usize = 450;
    if rdata.len() > MAX_TXT_LENGTH {
        Err(CheckError {
            summary: "Max TXT length exceeded".to_string(),
            description: format!(
                "SPF record length {} exceeds maximum allowed length of {}",
                rdata.len(),
                MAX_TXT_LENGTH
            ),
        })
    } else {
        Ok(())
    }
}

/// The character content of the record must be encoded as US-ASCII
pub fn check_is_ascii(rdata: &str) -> Result<(), CheckError> {
    if rdata.is_ascii() {
        Ok(())
    } else {
        let non_ascii_chars = rdata.chars().filter(|c| !c.is_ascii()).collect::<String>();
        Err(CheckError {
            summary: "Invalid SPF record".to_string(),
            description: format!(
                "SPF record contains non-ASCII characters! Following characters are not valid: '{}'",
                non_ascii_chars
            ),
        })
    }
}

pub fn check_version(rdata: &str) -> Result<(), CheckError> {
    let version = rdata.split(' ').next().unwrap_or("");
    match version {
        v if v == "v=spf1" => Ok(()),
        s if !s.starts_with("v=") => Err(CheckError {
            summary: "Invalid SPF version".to_string(),
            description: "Version must be defined first. SPF must start with the version 'v=spf1'"
                .to_string(),
        }),
        _ => Err(CheckError {
            summary: "Invalid SPF version".to_string(),
            description: format!(
                "The version '{}' is not valid. Version need to be 'v=spf1'",
                version
            ),
        }),
    }
}

pub fn check_has_unknown_term(terms: &[Term], _raw_rdata: &str) -> Result<bool, CheckError> {
    let unknown_terms = first_unknown_term(terms);

    if let Some(unknown_term) = unknown_terms {
        Err(CheckError {
            summary: "SPF record contains an unknown term".to_string(),
            description: format!("{} is an unknown term", unknown_term),
        })
    } else {
        Ok(true)
    }
}

pub fn check_all_is_rightmost(terms: &[Term], _raw_rdata: &str) -> Result<(), CheckError> {
    let directive_all_index = terms.iter().position(|term| match term {
        Term::Directive(d) => matches!(d.mechanism, Mechanism::All(_)),
        _ => false,
    });

    let Some(is_last) = directive_all_index else {
        return Ok(());
    };

    let ignored_terms = terms
        .iter()
        .skip(is_last + 1)
        .filter_map(|t| match t {
            Term::Directive(d) => Some(d.mechanism.to_string()),
            _ => None,
        })
        .collect::<Vec<String>>();

    if ignored_terms.is_empty() {
        Ok(())
    } else {
        Err(CheckError {
            summary: "Mechanisms after 'all' will be ignored".to_string(),
            description: format!(
                "Ignored terms: {}. Use 'all' mechanism as rightmost one",
                ignored_terms.join(", "),
            ),
        })
    }
}

pub fn check_no_redirect_with_all(terms: &[Term], _raw_rdata: &str) -> Result<(), CheckError> {
    let has_all_directive = terms.iter().any(|term| match term {
        Term::Directive(d) => matches!(d.mechanism, Mechanism::All(_)),
        _ => false,
    });
    let has_redirect_modifier = terms
        .iter()
        .any(|term| matches!(term, Term::Modifier(Modifier::Redirect(_))));

    if has_all_directive && has_redirect_modifier {
        Err(CheckError {
            summary: "SPF record contains 'all' directive and 'redirect' modifier".to_string(),
            description: "'redirect' modifier is ignored when 'all' directive is present"
                .to_string(),
        })
    } else {
        Ok(())
    }
}

pub fn check_lookup_count(terms: &[Term], _raw_rdata: &str) -> Result<usize, CheckError> {
    const MAX_LOOKUP_COUNT: usize = 10;

    let lookup_count = count_lookup(terms);

    if lookup_count > MAX_LOOKUP_COUNT {
        Err(CheckError {
            summary: "Max lookup count exceeded".to_string(),
            description: format!(
                "SPF record needs {} DNS lookups, which exceeds the maximum allowed of {}",
                lookup_count, MAX_LOOKUP_COUNT
            ),
        })
    } else {
        Ok(lookup_count)
    }
}

fn count_lookup(terms: &[Term]) -> usize {
    let current_count: usize = terms
        .iter()
        .map(|term| match term {
            Term::Directive(t) if t.mechanism.need_lookup() => {
                if let Mechanism::Include(i) = &t.mechanism {
                    count_lookup(&i.terms) + 1
                } else {
                    1
                }
            }
            Term::Modifier(m) if m.need_lookup() => 1,
            _ => 0,
        })
        .sum();

    current_count
}

fn first_unknown_term(terms: &[Term]) -> Option<&str> {
    let unknown_terms = terms.iter().filter_map(|term| match term {
        Term::Directive(d) => {
            if let Mechanism::Include(i) = &d.mechanism {
                first_unknown_term(&i.terms)
            } else {
                None
            }
        }
        Term::Unknown(UnknownTerm { raw_rdata }) => Some(raw_rdata),
        _ => None,
    });

    unknown_terms.to_owned().next()
}

#[cfg(test)]
mod test {
    use crate::spf::domain::{
        AMechanism, AllMechanism, Directive, IncludeMechanism, RedirectModifier, Version,
    };

    use super::*;

    #[test]
    fn test_unknown_term_check_returns_err() {
        let terms = vec![Term::Unknown(UnknownTerm {
            raw_rdata: "foo".to_string(),
        })];
        let result = check_has_unknown_term(&terms, "");

        assert!(result.is_err());
    }

    #[test]
    fn test_nested_unknown_term_check_returns_err() {
        let terms = vec![Term::Directive(Directive {
            mechanism: Mechanism::Include(IncludeMechanism {
                raw_value: "include:foo".to_string(),
                version: Version {
                    version: "".to_string(),
                },
                domain_spec: "".to_string(),
                terms: vec![Term::Unknown(UnknownTerm {
                    raw_rdata: "foo".to_string(),
                })],
                raw_rdata: "".to_string(),
            }),
            qualifier: None,
        })];
        let result = check_has_unknown_term(&terms, "");

        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_term_check_returns_ok() {
        let terms = vec![Term::Directive(Directive {
            mechanism: Mechanism::All(AllMechanism {
                raw_value: "all".to_string(),
            }),
            qualifier: None,
        })];
        let result = check_has_unknown_term(&terms, "").unwrap_or(false);

        assert!(result);
    }

    #[test]
    fn test_redirect_with_all_returns_err() {
        let terms = vec![
            Term::Directive(Directive {
                mechanism: Mechanism::All(AllMechanism {
                    raw_value: "all".to_string(),
                }),
                qualifier: None,
            }),
            Term::Modifier(Modifier::Redirect(RedirectModifier {
                raw_value: "".to_string(),
                version: Version {
                    version: "".to_string(),
                },
                domain_spec: "example.com".to_string(),
                terms: vec![],
                raw_rdata: "".to_string(),
            })),
        ];
        let result = check_no_redirect_with_all(&terms, "");

        assert!(result.is_err());
    }

    #[test]
    fn test_redirect_without_all_returns_ok() {
        let terms = vec![Term::Modifier(Modifier::Redirect(RedirectModifier {
            raw_value: "".to_string(),
            version: Version {
                version: "".to_string(),
            },
            domain_spec: "example.com".to_string(),
            terms: vec![],
            raw_rdata: "".to_string(),
        }))];
        let result = check_no_redirect_with_all(&terms, "");

        assert!(result.is_ok());
    }

    #[test]
    fn test_all_without_redirect_returns_ok() {
        let terms = vec![Term::Directive(Directive {
            mechanism: Mechanism::All(AllMechanism {
                raw_value: "all".to_string(),
            }),
            qualifier: None,
        })];
        let result = check_no_redirect_with_all(&terms, "");

        assert!(result.is_ok());
    }

    #[test]
    fn test_without_all_and_without_redirect_returns_ok() {
        let terms = vec![];
        let result = check_no_redirect_with_all(&terms, "");

        assert!(result.is_ok());
    }

    #[test]
    fn test_all_is_not_rightmost_returns_err() {
        let terms = vec![
            Term::Directive(Directive {
                mechanism: Mechanism::All(AllMechanism {
                    raw_value: "all".to_string(),
                }),
                qualifier: None,
            }),
            Term::Directive(Directive {
                mechanism: Mechanism::A(AMechanism {
                    raw_value: "a".to_string(),
                    ip_addresses: vec![],
                    subnet_mask: None,
                }),
                qualifier: None,
            }),
        ];
        let result = check_all_is_rightmost(&terms, "");

        assert!(result.is_err());
    }

    #[test]
    fn test_all_is_rightmost_returns_ok() {
        let terms = vec![
            Term::Directive(Directive {
                mechanism: Mechanism::A(AMechanism {
                    raw_value: "a".to_string(),
                    ip_addresses: vec![],
                    subnet_mask: None,
                }),
                qualifier: None,
            }),
            Term::Directive(Directive {
                mechanism: Mechanism::All(AllMechanism {
                    raw_value: "all".to_string(),
                }),
                qualifier: None,
            }),
        ];
        let result = check_all_is_rightmost(&terms, "");

        assert!(result.is_ok());
    }

    #[test]
    fn test_without_all_rightmost_returns_ok() {
        let terms = vec![];
        let result = check_all_is_rightmost(&terms, "");

        assert!(result.is_ok());
    }
}
