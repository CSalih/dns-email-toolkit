use crate::spf::domain::term::Term;
use crate::spf::domain::version::Version;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub enum Mechanism {
    All(AllMechanism),
    A(AMechanism),
    Include(IncludeMechanism),
    Mx(MxMechanism),
    Ptr(PtrMechanism),
    Ip4(Ip4Mechanism),
    Ip6(Ip6Mechanism),
    Exists(ExistsMechanism),
}

impl Mechanism {
    pub(crate) fn need_lookup(&self) -> bool {
        matches!(
            self,
            Mechanism::Include(_)
                | Mechanism::A(_)
                | Mechanism::Mx(_)
                | Mechanism::Ptr(_)
                | Mechanism::Exists(_)
        )
    }
}

impl FromStr for Mechanism {
    type Err = ();

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        Err(())
    }
}

impl Display for Mechanism {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Mechanism::All(m) => write!(f, "{}", m.raw_value),
            Mechanism::Include(m) => write!(f, "{}", m.raw_value),
            Mechanism::A(m) => write!(f, "{}", m.raw_value),
            Mechanism::Mx(m) => write!(f, "{}", m.raw_value),
            Mechanism::Ptr(m) => write!(f, "{}", m.raw_value),
            Mechanism::Ip4(m) => write!(f, "{}", m.raw_value),
            Mechanism::Ip6(m) => write!(f, "{}", m.raw_value),
            Mechanism::Exists(m) => write!(f, "{}", m.raw_value),
        }
    }
}

pub struct AllMechanism {
    /// The raw value of the mechanism
    pub raw_value: String,
}

pub struct AMechanism {
    /// The raw value of the mechanism
    pub raw_value: String,

    pub ip_addresses: Vec<IpAddr>,

    /// Subnet mask
    pub subnet_mask: Option<u8>,
}

pub struct IncludeMechanism {
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
pub struct MxMechanism {
    /// The raw value of the mechanism
    pub raw_value: String,

    pub hosts: Vec<String>,

    /// Subnet mask
    pub subnet_mask: Option<u8>,
}
pub struct PtrMechanism {
    /// The raw value of the mechanism
    pub raw_value: String,
}
pub struct Ip4Mechanism {
    /// The raw value of the mechanism
    pub raw_value: String,

    /// IPv4 address
    pub ip_address: Ipv4Addr,

    /// Subnet mask
    pub subnet_mask: Option<u8>,
}
pub struct Ip6Mechanism {
    /// The raw value of the mechanism
    pub raw_value: String,

    /// IPv6 address
    pub ip_address: Ipv6Addr,

    /// Subnet mask
    pub subnet_mask: Option<u8>,
}
pub struct ExistsMechanism {
    /// The raw value of the mechanism
    pub raw_value: String,
}
