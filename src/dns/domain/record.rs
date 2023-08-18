use std::net::IpAddr;

pub struct ARecord {
    pub ip_addresses: Vec<IpAddr>,
}

pub struct TxtRecord {
    pub records: Vec<String>,
}

pub struct MxRecord {
    pub exchanges: Vec<String>,
}
