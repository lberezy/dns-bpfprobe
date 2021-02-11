#![no_std]
#![no_main]

use dns_bpfprobe::dns_answer::MAX_DNS_RESPONSE_LEN;
// use one of the preludes
// use redbpf_probes::kprobe::prelude::*;
use redbpf_probes::xdp::prelude::*;
// use redbpf_probes::socket_filter::prelude::*;

// Use the types you're going to share with userspace, eg:
use dns_bpfprobe::dns_answer::DnsAnswerEvent;

#[map("events")]
static mut events: PerfMap<DnsAnswerEvent> = PerfMap::with_max_entries(10240);

program!(0xFFFFFFFE, "GPL");

mod parse {
    #[derive(Clone)]
    #[repr(packed)] // should this be repr(packed)?
    pub struct Header {
        /// "ID to keep track of request/responces"
        transaction_id: [u8; 2],
        flags: [u8; 2],
        /// "How many questions are there"
        qdcount: [u8; 2],
        /// "Number of resource records answering the question"
        ancount: [u8; 2],
        /// "Number of resource records pointing toward an authority"
        nscount: [u8; 2],
        /// "Number of resource records holding additional information"
        arcount: [u8; 2],
    }

    impl Header {
        #[inline]
        pub fn authoritative_answer(&self) -> bool {
            (self.flags[0] & 0b0000_0100) != 0
        }

        #[inline]
        pub fn is_query(&self) -> bool {
            (self.flags[0] & 0b1000_0000) == 0
        }

        #[inline]
        pub fn is_response(&self) -> bool {
            (self.flags[0] & 0b1000_0000) != 0
        }

        #[inline]
        pub fn response_count(&self) -> u16 {
            u16::from_be_bytes(self.ancount)
        }
    }
}

#[xdp]
pub fn dns_answer(ctx: XdpContext) -> XdpResult {

    // let ip = unsafe { *ctx.ip()? };
    let transport = ctx.transport()?;
    let data = ctx.data()?;
    // let buffer = unsafe {
    //     let ptr = ctx.ptr_at(0)? as *const u8 as *mut u8;
    //     core::slice::from_raw_parts_mut(ptr, crate::MAX_DNS_RESPONSE_LEN)
    // };

    let buffer = data.slice(crate::MAX_DNS_RESPONSE_LEN)?;

    // assert!(buffer == data.slice(crate::MAX_DNS_RESPONSE_LEN)?);

    if let Ok(transport) = ctx.transport() {
        if transport.dest() != 53 {
            return Ok(XdpAction::Pass);
        }
    }

    let header = unsafe {
        &*(buffer[0..core::mem::size_of::<parse::Header>()].as_ptr() as *const _
            as *const parse::Header)
    };

    // we only care about authoritative DNS responses
    if header.is_response() && header.response_count() != 0 && header.authoritative_answer() {
        // send this buffer to userspace
        return Ok(XdpAction::Pass);
    }

    Ok(XdpAction::Pass)
}
