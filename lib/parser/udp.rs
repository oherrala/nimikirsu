use untrusted::{Input, Reader};
use untrustended::{Error, ReaderExt};

#[derive(Debug)]
pub struct UdpPacket<'a> {
    pub source: u16,
    pub destination: u16,
    pub payload: Input<'a>,
}

impl<'a> UdpPacket<'a> {
    pub fn reader(input: &mut Reader<'a>) -> Result<Self, Error> {
        trace!("UdpPacket::reader");
        let source = input.read_u16be()?;
        let destination = input.read_u16be()?;

        let length = input.read_u16be()?;
        if length < 8 {
            error!("Invalid length for UDP: {}", length);
            return Err(Error::ParseError);
        }

        let _checksum = input.read_u16be(); // FIXME: check checksum
        let payload = input.skip_to_end();

        let payload_len = payload.len();
        if (length as usize - 8) != payload_len {
            error!("UDP payload doesn't match given length: Header promised {} bytes, payload is {} bytes", length-8, payload_len);
            return Err(Error::ParseError);
        }

        let packet = UdpPacket {
            source,
            destination,
            payload,
        };
        Ok(packet)
    }
}
