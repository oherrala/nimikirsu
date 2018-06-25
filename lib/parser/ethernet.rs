use untrusted::{Input, Reader};
use untrustended::{Error, ReaderExt};

use parser::ipv4::IPv4Packet;
use parser::ipv6::IPv6Packet;

pub type MacAddr = u64;

#[derive(Debug)]
pub struct EthernetFrame<'a> {
    pub destination: MacAddr,
    pub source: MacAddr,
    pub payload: EthernetPayload<'a>,
}

#[derive(Debug)]
pub enum EthernetPayload<'a> {
    IPv4(IPv4Packet<'a>),
    IPv6(IPv6Packet<'a>),
    Unknown(u16, Input<'a>),
}

impl<'a> EthernetFrame<'a> {
    pub fn reader(input: &mut Reader<'a>) -> Result<Self, Error> {
        trace!("EthernetFrame::reader");
        let destination = input.read_u48be()?;
        let source = input.read_u48be()?;
        let ethertype = input.read_u16be()?;
        let raw_payload = input.skip_to_end();

        let payload = match ethertype {
            0x0800 => {
                EthernetPayload::IPv4(raw_payload.read_all(Error::ParseError, IPv4Packet::reader)?)
            }
            0x86DD => {
                EthernetPayload::IPv6(raw_payload.read_all(Error::ParseError, IPv6Packet::reader)?)
            }
            n => EthernetPayload::Unknown(n, raw_payload),
        };

        let frame = EthernetFrame {
            destination,
            source,
            payload,
        };

        Ok(frame)
    }
}
