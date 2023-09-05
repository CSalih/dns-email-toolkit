use crate::spf::domain::{Term, Version};
use std::fmt::{Display, Formatter};

pub enum Modifier {
    Exp(ExpModifier),
    Redirect(RedirectModifier),
}

impl Modifier {
    pub(crate) fn need_lookup(&self) -> bool {
        matches!(self, Modifier::Redirect(_))
    }
}

impl Display for Modifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Modifier::Exp(e) => write!(f, "{}", e.raw_value),
            Modifier::Redirect(r) => write!(f, "{}", r.raw_value),
        }
    }
}

pub struct ExpModifier {
    pub raw_value: String,
}

pub struct RedirectModifier {
    /// The raw value of the mechanism
    pub raw_value: String,

    /// The version of the SPF record (e.g. "spf1")
    pub version: Version,

    /// The domain name of the included SPF record
    pub domain_spec: String,

    /// The list of directives or modifiers
    pub terms: Vec<Term>,

    /// RDATA of a single DNS TXT resource record
    pub raw_rdata: String,
}
