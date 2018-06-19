use std::net::Ipv4Addr;

use untrusted::{Input, Reader};
use untrustended::{self, ReaderExt};

pub mod dns;

pub type MacAddr = u64;

#[derive(Debug)]
pub struct EthernetFrame {
    pub destination: MacAddr,
    pub source: MacAddr,
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    pub fn try_from(buf: &[u8]) -> Result<Self, untrustended::Error> {
        trace!("EthernetFrame::try_from");
        let input = Input::from(buf);
        input.read_all(untrustended::Error::ParseError, Self::reader)
    }

    fn reader(input: &mut Reader) -> Result<Self, untrustended::Error> {
        let destination = input.read_u48be()?;
        let source = input.read_u48be()?;
        let ethertype = input.read_u16be()?;
        let payload = Vec::from(input.skip_to_end().as_slice_less_safe());

        let frame = EthernetFrame {
            destination,
            source,
            ethertype,
            payload,
        };
        Ok(frame)
    }
}

#[derive(Debug)]
pub struct IPv4Packet {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub ttl: u8,
    pub protocol: u8,
    pub payload: Vec<u8>,
}

impl IPv4Packet {
    pub fn try_from(buf: &[u8]) -> Result<Self, untrustended::Error> {
        trace!("IPv4Packet::try_from");
        let input = Input::from(buf);
        input.read_all(untrustended::Error::ParseError, Self::reader)
    }

    fn reader(input: &mut Reader) -> Result<Self, untrustended::Error> {
        let first_byte = input.read_u8()?;
        let version = first_byte >> 4;
        if version != 4 {
            warn!("Invalid version number for IPv4: {}", version);
            return Err(untrustended::Error::ParseError);
        }

        // Header length in bytes
        let header_len = (first_byte & 0b0000_1111) * 4;
        if header_len < 5 * 4 {
            warn!("Invalid header length for IPv4: {}", header_len);
            return Err(untrustended::Error::ParseError);
        }

        // Contains DSCP and ECN. We don't care.
        let _second_byte = input.read_u8()?;

        let total_len = input.read_u16be()?;
        if total_len < 20 {
            warn!("Invalid total length for IPv4: {}", total_len);
            return Err(untrustended::Error::ParseError);
        }

        let _identification = input.read_u16be()?;
        let _flags_and_fragment_offset = input.read_u16be()?;

        let ttl = input.read_u8()?;
        let protocol = input.read_u8()?;
        let _header_checksum = input.read_u16be()?; // FIXME: check checksum
        let source = input.read_ipv4addr()?;
        let destination = input.read_ipv4addr()?;

        // Options. We don't care.
        let _options = input.skip_and_get_input(usize::from(header_len - 20));

        let payload = Vec::from(input.skip_to_end().as_slice_less_safe());

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

#[derive(Debug)]
pub struct UdpPacket {
    pub source: u16,
    pub destination: u16,
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub fn try_from(buf: &[u8]) -> Result<Self, untrustended::Error> {
        trace!("UdpPacket::try_from");
        let input = Input::from(buf);
        input.read_all(untrustended::Error::ParseError, Self::reader)
    }

    fn reader(input: &mut Reader) -> Result<Self, untrustended::Error> {
        let source = input.read_u16be()?;
        let destination = input.read_u16be()?;

        let length = input.read_u16be()?;
        if length < 8 {
            warn!("Invalid length for UDP: {}", length);
            return Err(untrustended::Error::ParseError);
        }

        let _checksum = input.read_u16be(); // FIXME: check checksum
        let payload = Vec::from(input.skip_to_end().as_slice_less_safe());

        let payload_len = payload.len();
        if (length as usize - 8) != payload_len {
            warn!("UDP payload doesn't match given length: Header promised {} bytes, payload is {} bytes", length-8, payload_len);
            return Err(untrustended::Error::ParseError);
        }

        let packet = UdpPacket {
            source,
            destination,
            payload,
        };
        Ok(packet)
    }
}
