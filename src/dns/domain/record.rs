use std::net::Ipv4Addr;

pub struct ARecord {
    pub ip_addresses: Vec<Ipv4Addr>,
}

pub struct TxtRecord {
    pub records: Vec<String>,
}

pub struct MxRecord {
    pub exchanges: Vec<String>,
}
