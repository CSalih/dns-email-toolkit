mod directive;
mod error;
mod mechanism;
mod modifier;
mod qualifier;
mod term;
mod version;

pub use directive::Directive;
pub use error::{CheckError, SpfError};
pub use mechanism::{
    AMechanism, AllMechanism, IncludeMechanism, Ip4Mechanism, Ip6Mechanism, Mechanism, MxMechanism,
};
pub use qualifier::QualifierType;
pub use term::{Term, UnknownTerm};
pub use version::Version;
