use crate::spf::domain::mechanism::Mechanism;
use crate::spf::domain::qualifier::QualifierType;
use std::fmt::{Display, Formatter};

pub struct Directive {
    /// The qualifier of the directive
    pub qualifier: Option<QualifierType>,
    /// The "value" of the directive (e.g. "example.com" for redirect)
    pub mechanism: Mechanism,
}

impl Display for Directive {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // TODO: i bet this can be done better
        let qualifier: &str = match self.qualifier {
            None => "",
            Some(_) => self.qualifier.as_ref().unwrap().as_str(),
        };
        write!(f, "{}{}", qualifier, self.mechanism)
    }
}
