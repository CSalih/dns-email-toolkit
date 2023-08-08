use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

pub struct Version {
    pub version: String,
}

impl FromStr for Version {
    type Err = ();

    fn from_str(s: &str) -> Result<Version, Self::Err> {
        Ok(Version {
            version: s.to_string(),
        })
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.version)
    }
}

pub enum MechanismType {
    All,
    Include,
    A,
    Mx,
    Ptr,
    Ip4,
    Ip6,
    Exists,
}

impl MechanismType {
    fn as_str(&self) -> &'static str {
        match self {
            MechanismType::All => "all",
            MechanismType::Include => "include",
            MechanismType::A => "a",
            MechanismType::Mx => "mx",
            MechanismType::Ptr => "ptr",
            MechanismType::Ip4 => "ip4",
            MechanismType::Ip6 => "ip6",
            MechanismType::Exists => "exists",
        }
    }
}

impl FromStr for MechanismType {
    type Err = ();

    fn from_str(s: &str) -> Result<MechanismType, Self::Err> {
        match s {
            "all" => Ok(MechanismType::All),
            "include" => Ok(MechanismType::Include),
            "a" => Ok(MechanismType::A),
            "mx" => Ok(MechanismType::Mx),
            "ptr" => Ok(MechanismType::Ptr),
            "ip4" => Ok(MechanismType::Ip4),
            "ip6" => Ok(MechanismType::Ip6),
            "exists" => Ok(MechanismType::Exists),
            _ => Err(()),
        }
    }
}

pub struct Mechanism {
    /// The type of the mechanism
    pub mechanism_type: MechanismType,
    /// The "value" of the mechanism (e.g. "example.com" for include)
    pub domain_spec: String,
}

impl FromStr for Mechanism {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mechanism_str = s.to_string();
        // TODO: check if there is more then two results
        let (name, value) = mechanism_str
            .split_once(':')
            .unwrap_or((&mechanism_str, ""));

        match MechanismType::from_str(name) {
            Ok(mechanism_type) => Ok(Mechanism {
                mechanism_type,
                domain_spec: value.to_string(),
            }),
            Err(_) => Err(format!("Unknown mechanism type: {}", name)),
        }
    }
}

impl Display for Mechanism {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.mechanism_type.as_str(), self.domain_spec)
    }
}

#[derive(Default)]
pub enum QualifierType {
    /// The qualifier "+" means pass.
    #[default]
    Pass,
    /// The qualifier "-" means fail.
    Fail,
    /// The qualifier "~" means soft fail.
    SoftFail,
    /// The qualifier "?" means neutral.
    Neutral,
}

impl FromStr for QualifierType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "+" => Ok(QualifierType::Pass),
            "-" => Ok(QualifierType::Fail),
            "~" => Ok(QualifierType::SoftFail),
            "?" => Ok(QualifierType::Neutral),
            _ => Err(format!("Unknown mechanism type: {}", s)),
        }
    }
}

impl QualifierType {
    pub fn as_str(&self) -> &'static str {
        match self {
            QualifierType::Pass => "+",
            QualifierType::Fail => "-",
            QualifierType::SoftFail => "~",
            QualifierType::Neutral => "?",
        }
    }
}

/// (e.g. "+all", "include:example.com")
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

pub struct Modifier {}

pub struct Unknown {
    pub raw_rdata: String,
}

pub enum Term {
    Directive(Directive),
    Modifier(Modifier),
    Unknown(Unknown),
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
            Err(_) => Ok(Term::Unknown(Unknown {
                raw_rdata: mechanism_str.to_string(),
            })),
        }
    }
}
