use std::net::Ipv6Addr;

use untrusted::Reader;
use untrustended::{Error, ReaderExt};

use parser::IPPayload;

#[derive(Debug)]
pub struct IPv6Packet<'a> {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub next_header: u8,
    pub hop_limit: u8,
    pub payload: IPPayload<'a>,
}

impl<'a> IPv6Packet<'a> {
    pub fn reader(input: &mut Reader<'a>) -> Result<Self, Error> {
        trace!("IPv6Packet::reader");
        let first_quadbyte = input.read_u32be()?;
        let version = first_quadbyte >> 28;
        if version != 6 {
            error!("Invalid version number for IPv6: {}", version);
            return Err(Error::ParseError);
        }

        let _traffic_class = (first_quadbyte >> 20) & 0b1111_1111;
        let _flow_label = first_quadbyte & 0b0000_0000_0000_1111_1111_1111_1111_1111;

        let length = input.read_u16be()?;
        let next_header = input.read_u8()?;
        let hop_limit = input.read_u8()?;

        let source = input.read_ipv6addr()?;
        let destination = input.read_ipv6addr()?;

        let raw_payload = input.skip_and_get_input(length as usize)?;
        let payload = IPPayload::from_input(next_header, raw_payload)?;

        Ok(IPv6Packet {
            source,
            destination,
            hop_limit,
            next_header,
            payload,
        })
    }
}
