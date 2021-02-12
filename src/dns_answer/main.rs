#![no_std]
// #![feature(alloc, alloc_error_handler, panic_implementation)]
#![no_main]

// extern crate alloc;

use dns_bpfprobe::dns_answer::MAX_DNS_RESPONSE_LEN;
use dns_bpfprobe::dns_answer::{DnsAnswerEvent, Event};
use redbpf_probes::xdp::prelude::*;
// #[macro_use]
// use binread;
#[map("dns_queries")]
static mut events: PerfMap<Event> = PerfMap::with_max_entries(10240);

program!(0xFFFFFFFE, "GPL");

mod parse {
    // use alloc::vec::Vec;
    use core::u16;

    // use binread::BinRead;
    // #[br(big)]
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

    // #[derive(Clone, BinRead)]
    // #[br(big)]
    // #[repr(packed)] // should this be repr(packed)?
    // pub struct Query {
    //     name: ,
    //     kind: u16,
    //     kind_class: ,
    //     class_type: u16,
    // }

    // #[derive(Clone, BinRead)]
    // #[br(big)]
    // #[repr(packed)] // should this be repr(packed)?
    // pub struct Answer {}

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

    let (ip, transport, buffer) = match (ctx.ip(), ctx.transport(), ctx.data()) {
        // only want to deal with UDP DNS for now
        (Ok(ip), Ok(t @ Transport::UDP(_)), Ok(data)) => (unsafe { *ip }, t, data),
        // anything else we'll leave alone
        _ => return Ok(XdpAction::Pass),
    };

    let payload_size = core::cmp::min(ctx.len(), crate::MAX_DNS_RESPONSE_LEN);
    let buffer = buffer.slice(payload_size)?;

    // let buffer = unsafe {
    //     let ptr = ctx.ptr_at(0)? as *const u8 as *mut u8;
    //     core::slice::from_raw_parts_mut(ptr, crate::MAX_DNS_RESPONSE_LEN)
    // };

    // let buffer = data.slice(crate::MAX_DNS_RESPONSE_LEN)?;

    // assert!(buffer == data.slice(crate::MAX_DNS_RESPONSE_LEN)?);

    if let Ok(transport) = ctx.transport() {
        if transport.dest() != 53 {
            return Ok(XdpAction::Pass);
        }
    }

    // structure the header
    let header = unsafe {
        &*(buffer[0..core::mem::size_of::<parse::Header>()].as_ptr() as *const _
            as *const parse::Header)
    };

    // we only care about authoritative DNS responses
    if header.is_response() && header.response_count() != 0 && header.authoritative_answer() {
        let event = Event {
            saddr: ip.saddr,
            daddr: ip.daddr,
            sport: transport.source(),
            dport: transport.dest(),
        };
        // send this buffer to userspace
        unsafe {
            // casts from usize to u32 can panic
            events.insert(
                &ctx,
                &MapData::with_payload(event, ctx.data()?.offset() as u32, payload_size as u32),
            )
        }
    }

    Ok(XdpAction::Pass)
}
