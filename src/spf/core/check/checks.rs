use crate::spf::domain::{Mechanism, Term};

pub struct ErrorDetail {
    pub summary: String,
    pub description: String,
}

/// Records that are too long to fit in a single UDP packet
/// MAY be silently ignored by SPF clients.
pub fn check_max_txt_length(rdata: &str) -> Result<(), ErrorDetail> {
    const MAX_TXT_LENGTH: usize = 450;
    if rdata.len() > MAX_TXT_LENGTH {
        Err(ErrorDetail {
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

pub fn check_version(rdata: &str) -> Result<(), ErrorDetail> {
    let version = rdata.split(' ').next().unwrap_or("");
    match version {
        v if v == "v=spf1" => Ok(()),
        s if !s.starts_with("v=") => Err(ErrorDetail {
            summary: "Invalid SPF version".to_string(),
            description: "Version must be defined first. SPF must start with the version 'v=spf1'"
                .to_string(),
        }),
        _ => Err(ErrorDetail {
            summary: "Invalid SPF version".to_string(),
            description: format!(
                "The version '{}' is not valid. Version need to be 'v=spf1'",
                version
            ),
        }),
    }
}

pub fn check_lookup_count(terms: &[Term], _raw_rdata: &str) -> Result<usize, ErrorDetail> {
    const MAX_LOOKUP_COUNT: usize = 10;

    let lookup_count = count_lookup(terms);

    if lookup_count > MAX_LOOKUP_COUNT {
        Err(ErrorDetail {
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
