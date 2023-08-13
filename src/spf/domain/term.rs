use crate::spf::domain::directive::Directive;
use crate::spf::domain::mechanism::Mechanism;
use crate::spf::domain::modifier::Modifier;
use crate::spf::domain::qualifier::QualifierType;
use std::str::FromStr;

pub enum Term {
    Directive(Directive),
    Modifier(Modifier),
    Unknown(UnknownTerm),
}

impl FromStr for Term {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (qualifier, mechanism_str) = if s.starts_with(QualifierType::Pass.as_str()) {
            (QualifierType::Pass.as_str(), &s[1..])
        } else if s.starts_with(QualifierType::Fail.as_str()) {
            (QualifierType::Fail.as_str(), &s[1..])
        } else if s.starts_with(QualifierType::SoftFail.as_str()) {
            (QualifierType::SoftFail.as_str(), &s[1..])
        } else if s.starts_with(QualifierType::Neutral.as_str()) {
            (QualifierType::Neutral.as_str(), &s[1..])
        } else {
            ("", s)
        };
        let qualifier = match QualifierType::from_str(qualifier) {
            Ok(q) => Some(q),
            Err(_) => None,
        };

        match Mechanism::from_str(mechanism_str) {
            Ok(mechanism) => Ok(Term::Directive(Directive {
                qualifier,
                mechanism,
            })),
            Err(_) => Ok(Term::Unknown(UnknownTerm {
                raw_rdata: mechanism_str.to_string(),
            })),
        }
    }
}

pub struct UnknownTerm {
    pub raw_rdata: String,
}
