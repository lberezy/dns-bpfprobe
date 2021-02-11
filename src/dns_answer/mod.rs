
use cty::*;

pub const MAX_DOMAIN_NAME_LEN: usize = 253;
pub const MAX_DNS_RESPONSE_LEN: usize = 512; // maximum 512 bytes response size

// This is where you should define the types shared by the kernel and user
// space, eg:
//
#[repr(C)]
#[derive(Debug)]
pub struct DnsAnswerEvent {
    pub domain: DomainName,
    pub address: IpAddress,
    pub kind: QueryKind,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct DomainName {
    pub name: [u8; MAX_DOMAIN_NAME_LEN],
}

#[derive(Debug)]
#[repr(u64)]
pub enum QueryKind {
    IPv4(u32),
    IPv6(u128)
}


#[derive(Debug)]
#[repr(u64)]
pub enum IpAddress {
    IPv4(u32),
    IPv6(u128)
}
