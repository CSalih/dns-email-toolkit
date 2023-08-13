use std::str::FromStr;

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
