use untrusted::Input;
use untrustended::Error;

use parser::UdpPacket;

#[derive(Debug)]
pub enum IPPayload<'a> {
    UDP(UdpPacket<'a>),
    Unknown(u8, Input<'a>),
}

impl<'a> IPPayload<'a> {
    pub fn from_input(protocol: u8, input: Input<'a>) -> Result<Self, Error> {
        // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        let payload = match protocol {
            17 => IPPayload::UDP(input.read_all(Error::ParseError, UdpPacket::reader)?),
            n => IPPayload::Unknown(n, input),
        };

        Ok(payload)
    }
}
