use std::net::SocketAddr;

use untrusted::Input;
use untrustended::Error;

pub mod dns;

mod ethernet;
mod ip_common;
mod ipv4;
mod ipv6;
mod udp;

use self::{ethernet::*, ip_common::*, udp::*};

#[derive(Debug)]
pub struct ParsedPacket<'a> {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: Input<'a>,
}

impl<'a> ParsedPacket<'a> {
    pub fn try_from(buf: &'a [u8]) -> Result<Self, Error> {
        trace!("parse_protocol_stack");
        let input = Input::from(buf);

        let whole_frame = input.read_all(Error::ParseError, EthernetFrame::reader)?;

        let (source, destination, payload) = match whole_frame.payload {
            EthernetPayload::IPv4(ip4) => match ip4.payload {
                IPPayload::UDP(udp) => {
                    let source = From::from((ip4.source, udp.source));
                    let destination = From::from((ip4.destination, udp.destination));
                    (source, destination, udp.payload)
                }
                IPPayload::Unknown(n, payload) => {
                    error!("Unknown IP payload type {} payload: {:?}", n, payload);
                    return Err(Error::UnknownError);
                }
            },
            EthernetPayload::IPv6(ip6) => match ip6.payload {
                IPPayload::UDP(udp) => {
                    let source = From::from((ip6.source, udp.source));
                    let destination = From::from((ip6.destination, udp.destination));
                    (source, destination, udp.payload)
                }
                IPPayload::Unknown(n, payload) => {
                    error!("Unknown IP payload type {} payload: {:?}", n, payload);
                    return Err(Error::UnknownError);
                }
            },
            EthernetPayload::Unknown(n, payload) => {
                error!("Unknown Ethernet type {} payload: {:?}", n, payload);
                return Err(Error::UnknownError);
            }
        };

        let packet = Self {
            source,
            destination,
            payload,
        };
        debug!("Parsed {:?}", packet);

        Ok(packet)
    }
}
