use std::net::Ipv4Addr;

use untrusted::Reader;
use untrustended::{Error, ReaderExt};

use parser::IPPayload;

#[derive(Debug)]
pub struct IPv4Packet<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub ttl: u8,
    pub protocol: u8,
    pub payload: IPPayload<'a>,
}

impl<'a> IPv4Packet<'a> {
    pub fn reader(input: &mut Reader<'a>) -> Result<Self, Error> {
        trace!("IPv4Packet::reader");
        let first_byte = input.read_u8()?;
        let version = first_byte >> 4;
        if version != 4 {
            error!("Invalid version number for IPv4: {}", version);
            return Err(Error::ParseError);
        }

        // Header length in bytes
        let header_len = (first_byte & 0b0000_1111) * 4;
        if header_len < 20 || header_len > 60 {
            error!("Invalid header length for IPv4: {}", header_len);
            return Err(Error::ParseError);
        }

        // Contains DSCP and ECN. We don't care.
        let _second_byte = input.read_u8()?;

        let total_len = input.read_u16be()?;
        if total_len < 20 {
            error!("Invalid total length for IPv4: {}", total_len);
            return Err(Error::ParseError);
        }

        let _identification = input.read_u16be()?;
        let _flags_and_fragment_offset = input.read_u16be()?;

        let ttl = input.read_u8()?;
        let protocol = input.read_u8()?;
        let _header_checksum = input.read_u16be()?; // FIXME: check checksum
        let source = input.read_ipv4addr()?;
        let destination = input.read_ipv4addr()?;

        // Options. We don't care.
        let options_len = usize::from(header_len - 20);
        let _options = input.skip_and_get_input(options_len)?;

        let raw_payload = input.skip_to_end();
        let payload = IPPayload::from_input(protocol, raw_payload)?;

        let packet = IPv4Packet {
            source,
            destination,
            ttl,
            protocol,
            payload,
        };

        Ok(packet)
    }
}
