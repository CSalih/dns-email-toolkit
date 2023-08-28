use crate::spf::domain::{CheckError, Mechanism, Term, UnknownTerm};

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
    let unknown_term = terms.iter().find(|term| matches!(term, Term::Unknown(_)));

    if let Some(unknown_term) = unknown_term {
        let raw_value = match unknown_term {
            Term::Unknown(UnknownTerm { raw_rdata }) => raw_rdata,
            _ => unreachable!("we already filtered unknown terms"),
        };

        Err(CheckError {
            summary: "SPF record contains an unknown term".to_string(),
            description: format!("{} is an unknown term", raw_value),
        })
    } else {
        Ok(true)
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

#[cfg(test)]
mod test {
    use crate::spf::domain::{AllMechanism, Directive};

    use super::*;

    #[test]
    fn test_unknown_term_check_returns_err() {
        let terms = vec![Term::Unknown(UnknownTerm {
            raw_rdata: "foo".to_string(),
        })];

        let result = check_has_unknown_term(&terms, "");

        assert!(matches!(result, Err(_)));
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
}
