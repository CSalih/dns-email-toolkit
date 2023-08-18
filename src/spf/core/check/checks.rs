use crate::spf::domain::{CheckError, Mechanism, Term};

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
