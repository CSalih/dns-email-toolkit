use crate::spf::domain::{
    LabelSpan, Mechanism, Modifier, Severity, SyntaxError, Term, UnknownTerm,
};

/// Records that are too long to fit in a single UDP packet
/// MAY be silently ignored by SPF clients.
pub fn check_max_txt_length(rdata: &str) -> Result<(), Box<SyntaxError>> {
    const MAX_TXT_LENGTH: usize = 450;
    if rdata.len() <= MAX_TXT_LENGTH {
        Ok(())
    } else {
        let rdata_short = format!(
            "{}...{}",
            &rdata[..MAX_TXT_LENGTH / 6],
            &rdata[rdata.len() - MAX_TXT_LENGTH / 6..]
        );

        let span = 0..rdata_short.len();
        Err(Box::new(
            SyntaxError::new("Max length exceeded")
                .with_src(rdata_short)
                .with_src_labels(vec![LabelSpan::at(
                    span,
                    format!(
                        "Current length of {} exceeds maximum allowed length of {}.",
                        &rdata.len(),
                        MAX_TXT_LENGTH
                    ),
                )])
                .with_help("Reduce the length of the SPF record."),
        ))
    }
}

/// The character content of the record must be encoded as US-ASCII
pub fn check_is_ascii(rdata: &str) -> Result<(), Box<SyntaxError>> {
    if rdata.is_ascii() {
        Ok(())
    } else {
        let non_ascii_chars = rdata.chars().filter(|c| !c.is_ascii()).collect::<String>();
        // TODO: There os a bug in the code below. The spans are not correct.
        let spans = non_ascii_chars
            .chars()
            .filter_map(|c| rdata.chars().position(|r| r == c))
            .map(|pos| LabelSpan::at_offset(pos, "Non-ASCII character not allowed."))
            .collect::<Vec<LabelSpan>>();

        Err(Box::new(
            SyntaxError::new("Invalid character in SPF record")
                .with_src(rdata)
                .with_src_labels(spans)
                .with_help(format!("Remove {} from the SPF record.", non_ascii_chars)),
        ))
    }
}

pub fn check_version(rdata: &str) -> Result<(), Box<SyntaxError>> {
    let version = rdata.split(' ').next().unwrap_or("");
    match version {
        "v=spf1" => Ok(()),
        s if !s.starts_with("v=") => {
            let span = rdata.find(' ').map(|pos| 0..pos).unwrap_or(0..rdata.len());
            Err(Box::new(
                SyntaxError::new("Version must be defined")
                    .with_src(rdata)
                    .with_src_labels(vec![LabelSpan::at(span, "Version is missing")])
                    .with_help("Add 'v=spf1' to the beginning of the SPF record."),
            ))
        }
        _ => {
            let span = rdata.find(' ').map(|pos| 0..pos).unwrap_or(0..rdata.len());
            Err(Box::new(
                SyntaxError::new("Invalid SPF version")
                    .with_src(rdata)
                    .with_src_labels(vec![LabelSpan::at(
                        span,
                        format!("'{}' is not a valid version.", version),
                    )])
                    .with_help("Add 'v=spf1' to the beginning of the SPF record."),
            ))
        }
    }
}

pub fn check_has_unknown_term(terms: &[Term], raw_rdata: &str) -> Result<bool, Box<SyntaxError>> {
    let unknown_terms = unknown_terms(terms);
    if unknown_terms.is_empty() {
        return Ok(true);
    }

    Err(Box::new(
        SyntaxError::new("SPF record contains one or more unknown terms")
            .with_severity(Severity::Warning)
            .with_src(raw_rdata)
            .with_src_labels(unknown_terms.iter().map(|unknown_term| {
                let search_term = format!(" {}", &unknown_term.raw_rdata);
                let span_begin = if let Some(index) = raw_rdata.find(search_term.as_str()) {
                    index + 1
                } else {
                    0
                };

                let span_end = span_begin + unknown_term.raw_rdata.len();
                let span_range = span_begin..span_end;

                LabelSpan::at(
                    span_range,
                    format!("{} is an unknown term", unknown_term.raw_rdata),
                )
            }))
            .with_help(if unknown_terms.len() == 1 {
                format!("Remove the unknown term '{}'", &unknown_terms[0].raw_rdata)
            } else {
                format!(
                    "Remove the unknown terms '{}'",
                    &unknown_terms
                        .iter()
                        .map(|t| String::from(&t.raw_rdata))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }),
    ))
}

pub fn check_all_is_rightmost(terms: &[Term], raw_rdata: &str) -> Result<(), Box<SyntaxError>> {
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
        let span = raw_rdata
            .find(" all ")
            .map(|pos| pos + 5..raw_rdata.len())
            .unwrap_or(0..raw_rdata.len());

        Err(Box::new(
            SyntaxError::new("Mechanisms after 'all' found")
                .with_severity(Severity::Warning)
                .with_src(raw_rdata)
                .with_src_labels(vec![LabelSpan::at(span, "This will be ignored")])
                .with_help("Move 'all' to the end."),
        ))
    }
}

pub fn check_no_redirect_with_all(terms: &[Term], raw_rdata: &str) -> Result<(), Box<SyntaxError>> {
    let has_all_directive = terms.iter().any(|term| match term {
        Term::Directive(d) => matches!(d.mechanism, Mechanism::All(_)),
        _ => false,
    });
    let has_redirect_modifier = terms
        .iter()
        .any(|term| matches!(term, Term::Modifier(Modifier::Redirect(_))));

    if has_all_directive && has_redirect_modifier {
        let span = raw_rdata
            .find(" redirect")
            .map(|pos| pos + 1..pos + 9)
            .unwrap_or(0..raw_rdata.len());
        Err(Box::new(SyntaxError::new("SPF record contains 'all' directive and 'redirect' modifier")
            .with_severity(Severity::Warning)
            .with_src(raw_rdata)
            .with_src_labels(vec![LabelSpan::at(
                span, "'redirect' modifier is ignored when 'all' directive is present",
            )])
            .with_severity(Severity::Warning)
            .with_help("For clarity, any redirect modifier should appear as the very last term in a record."))
        )
    } else {
        Ok(())
    }
}

pub fn check_redirect_is_rightmost(
    terms: &[Term],
    _raw_rdata: &str,
) -> Result<(), Box<SyntaxError>> {
    let last_index = terms.len().saturating_sub(1);

    terms
        .iter()
        .position(|term| matches!(term, Term::Modifier(Modifier::Redirect(_))))
        .or(Some(last_index))
        .map(|index| {
            if index == last_index {
                Ok(())
            } else {
                Err(Box::new(SyntaxError::new("Redirect modifier not rightmost")
                    .with_severity(Severity::Warning)
                    .with_help("For clarity, any redirect modifier should appear as the very last term in a record."))
                )
            }
        }).expect("position should not be empty")
}

pub fn check_lookup_count(terms: &[Term], _raw_rdata: &str) -> Result<usize, Box<SyntaxError>> {
    const MAX_LOOKUP_COUNT: usize = 10;

    let lookup_count = count_lookup(terms);
    if lookup_count > MAX_LOOKUP_COUNT {
        Err(Box::new(
            SyntaxError::new(format!("Max lookup count of {} exceeded", MAX_LOOKUP_COUNT))
                .with_help(
                "Remove the excessive lookups (a, mx, ptr, include or exists) from the SPF record.",
            ),
        ))
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

fn unknown_terms(terms: &[Term]) -> Vec<&UnknownTerm> {
    let unknown_terms = terms
        .iter()
        .filter_map(|term| match term {
            // Term::Directive(d) => {
            //     if let Mechanism::Include(i) = &d.mechanism {
            //         let terms = unknown_terms(&i.terms);
            //         Some(terms)
            //         None
            //     } else {
            //         None
            //     }
            // }
            Term::Unknown(unknown) => Some(vec![unknown]),
            _ => None,
        })
        .flatten();

    unknown_terms.collect()
}

#[cfg(test)]
mod test {
    use crate::spf::domain::{
        AMechanism, AllMechanism, Directive, IncludeMechanism, RedirectModifier, Version,
    };

    use super::*;

    #[test]
    fn test_unknown_term_check_returns_err() {
        let terms = vec![Term::with_unknown()];
        let result = check_has_unknown_term(&terms, "");

        assert!(result.is_err());
    }

    #[test]
    #[ignore] // We do not support error labels over multiple sources yet
    fn test_nested_unknown_term_check_returns_err() {
        let terms = vec![Term::with_include_and_nested_unknown()];
        let result = check_has_unknown_term(&terms, "");

        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_term_check_returns_ok() {
        let terms = vec![Term::with_all()];
        let result = check_has_unknown_term(&terms, "").unwrap_or(false);

        assert!(result);
    }

    #[test]
    fn test_redirect_with_all_returns_err() {
        let terms = vec![Term::with_all(), Term::with_redirect()];
        let result = check_no_redirect_with_all(&terms, "");

        assert!(result.is_err());
    }

    #[test]
    fn test_redirect_without_all_returns_ok() {
        let terms = vec![Term::with_redirect()];
        let result = check_no_redirect_with_all(&terms, "");

        assert!(result.is_ok());
    }

    #[test]
    fn test_all_without_redirect_returns_ok() {
        let terms = vec![Term::with_all()];
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
        let terms = vec![Term::with_all(), Term::with_a()];
        let result = check_all_is_rightmost(&terms, "");

        assert!(result.is_err());
    }

    #[test]
    fn test_all_is_rightmost_returns_ok() {
        let terms = vec![Term::with_a(), Term::with_all()];
        let result = check_all_is_rightmost(&terms, "");

        assert!(result.is_ok());
    }

    #[test]
    fn test_without_all_rightmost_returns_ok() {
        let terms = vec![];
        let result = check_all_is_rightmost(&terms, "");

        assert!(result.is_ok());
    }

    #[test]
    fn test_redirect_is_not_rightmost_returns_err() {
        let terms = vec![Term::with_redirect(), Term::with_a()];
        let result = check_redirect_is_rightmost(&terms, "");

        assert!(result.is_err());
    }

    #[test]
    fn test_without_redirect_returns_ok() {
        let terms = vec![Term::with_a()];
        let result = check_redirect_is_rightmost(&terms, "");

        assert!(result.is_ok());
    }

    #[test]
    fn test_redirect_is_rightmost_returns_ok() {
        let terms = vec![Term::with_a(), Term::with_redirect()];
        let result = check_redirect_is_rightmost(&terms, "");

        assert!(result.is_ok());
    }

    impl Term {
        fn with_unknown() -> Self {
            Term::Unknown(UnknownTerm {
                raw_rdata: "".to_string(),
            })
        }

        fn with_include_and_nested_unknown() -> Self {
            Term::Directive(Directive {
                mechanism: Mechanism::Include(IncludeMechanism {
                    raw_value: "".to_string(),
                    version: Version {
                        version: "".to_string(),
                    },
                    domain_spec: "".to_string(),
                    terms: vec![Term::with_unknown()],
                    raw_rdata: "".to_string(),
                }),
                qualifier: None,
            })
        }

        fn with_all() -> Self {
            Term::Directive(Directive {
                mechanism: Mechanism::All(AllMechanism {
                    raw_value: "".to_string(),
                }),
                qualifier: None,
            })
        }

        pub fn with_redirect() -> Self {
            Term::Modifier(Modifier::Redirect(RedirectModifier {
                raw_value: "".to_string(),
                version: Version {
                    version: "".to_string(),
                },
                domain_spec: "".to_string(),
                terms: vec![],
                raw_rdata: "".to_string(),
            }))
        }

        pub fn with_a() -> Self {
            Term::Directive(Directive {
                mechanism: Mechanism::A(AMechanism {
                    raw_value: "".to_string(),
                    ip_addresses: vec![],
                    subnet_mask: None,
                }),
                qualifier: None,
            })
        }
    }
}
