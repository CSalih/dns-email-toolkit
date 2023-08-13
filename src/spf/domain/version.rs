use std::fmt::{Display, Formatter};
use std::str::FromStr;

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
