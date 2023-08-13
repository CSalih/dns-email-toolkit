mod directive;
mod error;
mod mechanism;
mod modifier;
mod qualifier;
mod term;
mod version;

pub use directive::Directive;
pub use error::SpfError;
pub use mechanism::{
    AMechanism, AllMechanism, IncludeMechanism, Ip4Mechanism, Ip6Mechanism, Mechanism,
};
pub use qualifier::QualifierType;
pub use term::{Term, UnknownTerm};
pub use version::Version;
