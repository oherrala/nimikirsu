use std::net::{Ipv4Addr, Ipv6Addr};

use untrusted::{Input, Mark, Reader};
use untrustended::Error::ParseError;
use untrustended::{self, ReaderExt};

/// +---------------------+
/// |        Header       |
/// +---------------------+
/// |       Question      | the question for the name server
/// +---------------------+
/// |        Answer       | RRs answering the question
/// +---------------------+
/// |      Authority      | RRs pointing toward an authority
/// +---------------------+
/// |      Additional     | RRs holding additional information
/// +---------------------+
#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub question: Vec<Question>,
    pub answer: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

impl Message {
    pub fn try_from(buf: &[u8]) -> Result<Self, untrustended::Error> {
        trace!("Message::try_from");
        let input = Input::from(buf);
        input.read_all(ParseError, Self::reader)
    }

    pub fn reader(input: &mut Reader) -> Result<Self, untrustended::Error> {
        trace!("Message::reader");
        let mark = input.mark();
        let header: Header = Header::reader(input)?;
        let mut question = Vec::with_capacity(usize::from(header.qdcount));
        let mut answer = Vec::with_capacity(usize::from(header.ancount));
        let mut authority = Vec::with_capacity(usize::from(header.nscount));
        let mut additional = Vec::with_capacity(usize::from(header.arcount));

        for i in 0..header.qdcount {
            trace!("Reading question {}/{}", i + 1, header.qdcount);
            let read_so_far: Input = input.get_input_between_marks(mark, input.mark())?;
            trace!("read_so_far: {:?}", read_so_far);
            let q = Question::reader(read_so_far, input)?;
            trace!("Read question {}: {:?}", i + 1, q);
            question.push(q);
        }

        for i in 0..header.ancount {
            trace!("Reading answer {}/{}", i + 1, header.ancount);
            let r = ResourceRecord::reader(mark, input)?;
            trace!("Read answer {}: {:?}", i + 1, r);
            answer.push(r);
        }

        for i in 0..header.nscount {
            trace!("Reading authority {}/{}", i + 1, header.nscount);
            let r = ResourceRecord::reader(mark, input)?;
            trace!("Read authority {}: {:?}", i + 1, r);
            authority.push(r);
        }

        for i in 0..header.arcount {
            trace!("Reading additional {}/{}", i + 1, header.arcount);
            let r = ResourceRecord::reader(mark, input)?;
            trace!("Read additional {}: {:?}", i + 1, r);
            additional.push(r);
        }

        Ok(Message {
            header,
            question,
            answer,
            authority,
            additional,
        })
    }
}

///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug)]
pub struct Header {
    pub id: u16,
    pub qr: Qr,
    pub opcode: Opcode,
    pub authority: bool,
    pub truncation: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: Rcode,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Debug)]
pub enum Qr {
    Query,
    Response,
}

#[derive(Debug)]
pub enum Opcode {
    Query,
    IQuery,
    Status,
    FutureUse(u8),
}

#[derive(Debug)]
pub enum Rcode {
    /// 0 No error condition
    NoError,
    /// 1 Format error - The name server was unable to interpret the query.
    FormatError,
    /// 2 Server failure - The name server was unable to process this query due
    /// to a problem with the name server.
    ServerFailure,
    /// 3 Name Error - Meaningful only for responses from an authoritative name
    /// server, this code signifies that the domain name referenced in the query
    /// does not exist.
    NameError,
    /// 4 Not Implemented - The name server does not support the requested kind
    /// of query.
    NotImplemented,
    /// 5 Refused - The name server refuses to perform the specified operation
    /// for policy reasons.  For example, a name server may not wish to provide
    /// the information to the particular requester, or a name server may not
    /// wish to perform a particular operation (e.g., zone transfer) for
    /// particular data.
    Refused,
    /// 6-15 Reserved for future use
    FutureUse(u8),
}

impl Header {
    fn reader(input: &mut Reader) -> Result<Self, untrustended::Error> {
        trace!("Header::reader");
        let id = input.read_u16be()?;
        let bitfield = input.read_u16be()?;

        let qr = if bitfield & 0b1000_0000_0000_0000 == 0 {
            Qr::Query
        } else {
            Qr::Response
        };

        let opcode = match bitfield & 0b0111_1000_0000_0000 >> 12 {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            n => Opcode::FutureUse(n as u8),
        };

        let authority = bitfield & 0b0000_1000_0000_0000 > 0;
        let truncation = bitfield & 0b0000_0100_0000_0000 > 0;
        let recursion_desired = bitfield & 0b0000_0010_0000_0000 > 0;
        let recursion_available = bitfield & 0b0000_0001_0000_0000 > 0;

        // Reserved for future use.  Must be zero in all queries and responses.
        // However, we skip validation because later specs (than RFC1035) might
        // define some use for this field.
        let _z = bitfield & 0b0000_0000_0111_0000;

        let rcode = match bitfield & 0b0000_0000_0000_1111 {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            5 => Rcode::Refused,
            n => Rcode::FutureUse(n as u8),
        };

        let qdcount = input.read_u16be()?;
        let ancount = input.read_u16be()?;
        let nscount = input.read_u16be()?;
        let arcount = input.read_u16be()?;

        let header = Header {
            id,
            qr,
            opcode,
            authority,
            truncation,
            recursion_desired,
            recursion_available,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        };
        Ok(header)
    }
}

///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                     QNAME                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QTYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QCLASS                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug)]
pub struct Question {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl Question {
    fn reader(read_so_far: Input, input: &mut Reader) -> Result<Self, untrustended::Error> {
        trace!("Question::reader");
        let qname = read_name(read_so_far, input)?;
        let qtype = input.read_u16be()?;
        let qclass = input.read_u16be()?;
        Ok(Question {
            qname,
            qtype,
            qclass,
        })
    }
}

///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                                               /
/// /                      NAME                     /
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     CLASS                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TTL                      |
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                   RDLENGTH                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/// /                     RDATA                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug)]
pub struct ResourceRecord {
    /// NAME a domain name to which this resource record pertains.
    pub name: String,

    /// TYPE two octets containing one of the RR type codes.  This field
    /// specifies the meaning of the data in the RDATA field.

    /// CLASS two octets which specify the class of the data in the RDATA field.
    pub class: Class,

    /// TTL a 32 bit unsigned integer that specifies the time interval (in seconds) that the resource record may be cached before it should be discarded.  Zero values are interpreted to mean that the RR can only be used for the transaction in progress, and should not be cached.
    pub ttl: u32,

    /// RDLENGTH an unsigned 16 bit integer that specifies the length in octets
    /// of the RDATA field.

    /// RDATA a variable length string of octets that describes the resource.
    /// The format of this information varies according to the TYPE and CLASS of
    /// the resource record. For example, the if the TYPE is A and the CLASS is
    /// IN, the RDATA field is a 4 octet ARPA Internet address.
    pub rdata: RData,
}

#[derive(Debug)]
pub enum RData {
    Cname(String),
    IPv4Addr(Ipv4Addr),
    IPv6Addr(Ipv6Addr),
    Mx((u16, String)),
    Ns(String),
    Opt(),
    Ptr(String),
    Soa(),
    Txt(),
    UnhandledType(u16),
}

#[derive(Debug)]
pub enum Class {
    IN,
    Unknown(u16),
}

impl ResourceRecord {
    fn reader(mark1: Mark, input: &mut Reader) -> Result<Self, untrustended::Error> {
        trace!("ResourceRecord::reader");
        let name = {
            let mark2 = input.mark();
            let read_so_far = input.get_input_between_marks(mark1, mark2)?;
            read_name(read_so_far, input)?
        };

        let rr_type = input.read_u16be()?;

        let raw_class = input.read_u16be()?;
        // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
        let class = match raw_class {
            1 => Class::IN,
            n => Class::Unknown(n),
        };

        let ttl = input.read_u32be()?;
        trace!("Read TTL: {}", ttl);

        let rdlength = input.read_u16be()?;
        trace!("Read RData length: {}", rdlength);

        let mark2 = input.mark();
        let read_so_far = input.get_input_between_marks(mark1, mark2)?;

        let rdata_raw = input.skip_and_get_input(rdlength as usize)?;
        let rdata: RData = match rr_type {
            // A     1 a host address
            1 => RData::IPv4Addr(rdata_raw.read_all(ParseError, |i| i.read_ipv4addr())?),
            // NS    2 an authoritative name server
            2 => RData::Ns(rdata_raw.read_all(ParseError, |i| read_name(read_so_far, i))?),
            // MD    3 a mail destination (Obsolete - use MX)
            // MF    4 a mail forwarder (Obsolete - use MX)
            // CNAME 5 the canonical name for an alias
            5 => RData::Cname(rdata_raw.read_all(ParseError, |i| read_name(read_so_far, i))?),
            // SOA   6 marks the start of a zone of authority
            6 => RData::Soa(),
            // MB    7 a mailbox domain name (EXPERIMENTAL)
            // MG    8 a mail group member (EXPERIMENTAL)
            // MR    9 a mail rename domain name (EXPERIMENTAL)
            // NULL  10 a null RR (EXPERIMENTAL)
            // WKS   11 a well known service description
            // PTR   12 a domain name pointer
            12 => RData::Ptr(rdata_raw.read_all(ParseError, |i| read_name(read_so_far, i))?),
            // HINFO 13 host information
            // MINFO 14 mailbox or mail list information
            // MX    15 mail exchange
            15 => rdata_raw.read_all(ParseError, |i| {
                let preference = i.read_u16be()?;
                let exchange = read_name(read_so_far, i)?;
                Ok(RData::Mx((preference, exchange)))
            })?,
            // AAAA 28  The AAAA resource record type is a record specific to
            // the Internet class that stores a single IPv6 address.
            // https://tools.ietf.org/html/rfc3596
            28 => RData::IPv6Addr(rdata_raw.read_all(ParseError, |i| i.read_ipv6addr())?),
            // TXT   16 text strings
            16 => RData::Txt(),
            // OPT 44 An OPT pseudo-RR (sometimes called a meta-RR) MAY be added
            // to the additional data section of a request.
            // https://tools.ietf.org/html/rfc6891
            44 => RData::Opt(),
            n => RData::UnhandledType(n),
        };
        trace!("Read RData: {:?}", rdata);

        Ok(ResourceRecord {
            name,
            class,
            ttl,
            rdata,
        })
    }
}

/// a domain name represented as a sequence of labels, where each label consists
/// of a length octet followed by that number of octets.  The domain name
/// terminates with the zero length octet for the null label of the root.  Note
/// that this field may be an odd number of octets; no padding is used.
fn read_name(read_so_far: Input, input: &mut Reader) -> Result<String, untrustended::Error> {
    trace!(
        "read_name. read_so_far: {:?}, input: {:?}",
        read_so_far,
        input
    );
    let mut name: Vec<String> = Vec::new();
    let mut name_len: usize = 0;

    loop {
        let len: u8 = input.read_u8()?;
        if len == 0 {
            trace!("null label encountered. label reading done.");
            break;
        }

        trace!("DNS label length field: {}", len);
        let offset: usize = if (len >> 6) == 0b11 {
            debug!("DNS label compression found");
            let first_byte = len & 0b0011_1111;
            let second_byte = input.read_u8()?;
            (usize::from(first_byte) << 8) + usize::from(second_byte)
        } else {
            0
        };

        let label = if offset > 0 {
            trace!("Reading compressed DNS label (offset {})", offset);

            let label = read_so_far.read_all(ParseError, |input| {
                let mark1 = input.mark();
                input.skip(offset)?;
                let mark2 = input.mark();
                // This ensures we can only look the past labels
                let read_so_far = input.get_input_between_marks(mark1, mark2)?;
                let name = read_name(read_so_far, input)?;
                let _ = input.skip_to_end();
                Ok(name)
            })?;

            trace!("Read compressed label(s) \"{}\"", label);
            name_len += label.len();
            label
        } else {
            if len > 63 {
                warn!("Invalid DNS label length: {}", len);
                return Err(ParseError);
            }

            let bytes = input.read_bytes_less_safe(len as usize)?;
            let label = String::from_utf8_lossy(bytes);

            trace!("Read label \"{}\"", label);
            name_len += usize::from(len);
            label.to_string()
        };

        name.push(label);
        if name_len > 255 {
            warn!("Too long DNS name: {}", name.len());
            return Err(ParseError);
        }

        if offset > 0 {
            break;
        }
    }

    if name.is_empty() {
        let name = String::from(".");
        debug!("Encountered DNS root: \"{}\"", name);
        return Ok(name);
    }

    let name = name.join(".");
    debug!("Reading name done: \"{}\"", name);
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns1() {
        let buf = [
            0, 0, 132, 0, 0, 0, 0, 1, 0, 0, 0, 3, 11, 95, 103, 111, 111, 103, 108, 101, 99, 97,
            115, 116, 4, 95, 116, 99, 112, 5, 108, 111, 99, 97, 108, 0, 0, 12, 0, 1, 0, 0, 0, 120,
            0, 46, 43, 67, 104, 114, 111, 109, 101, 99, 97, 115, 116, 45, 48, 50, 52, 101, 98, 54,
            50, 98, 99, 49, 56, 48, 51, 97, 48, 102, 56, 57, 100, 52, 99, 101, 56, 55, 100, 51, 54,
            56, 55, 48, 56, 51, 192, 12, 192, 46, 0, 16, 128, 1, 0, 0, 17, 148, 0, 168, 35, 105,
            100, 61, 48, 50, 52, 101, 98, 54, 50, 98, 99, 49, 56, 48, 51, 97, 48, 102, 56, 57, 100,
            52, 99, 101, 56, 55, 100, 51, 54, 56, 55, 48, 56, 51, 35, 99, 100, 61, 52, 51, 69, 55,
            50, 54, 50, 54, 67, 54, 53, 65, 56, 68, 50, 55, 65, 48, 65, 54, 49, 57, 68, 65, 48, 50,
            49, 54, 53, 50, 65, 49, 3, 114, 109, 61, 5, 118, 101, 61, 48, 53, 13, 109, 100, 61, 67,
            104, 114, 111, 109, 101, 99, 97, 115, 116, 18, 105, 99, 61, 47, 115, 101, 116, 117,
            112, 47, 105, 99, 111, 110, 46, 112, 110, 103, 14, 102, 110, 61, 79, 108, 107, 107, 97,
            114, 105, 99, 97, 115, 116, 7, 99, 97, 61, 52, 49, 48, 49, 4, 115, 116, 61, 48, 15, 98,
            115, 61, 70, 65, 56, 70, 67, 65, 51, 56, 54, 55, 69, 53, 4, 110, 102, 61, 49, 3, 114,
            115, 61, 192, 46, 0, 33, 128, 1, 0, 0, 0, 120, 0, 45, 0, 0, 0, 0, 31, 73, 36, 48, 50,
            52, 101, 98, 54, 50, 98, 45, 99, 49, 56, 48, 45, 51, 97, 48, 102, 45, 56, 57, 100, 52,
            45, 99, 101, 56, 55, 100, 51, 54, 56, 55, 48, 56, 51, 192, 29, 193, 34, 0, 1, 128, 1,
            0, 0, 0, 120, 0, 4, 172, 17, 2, 1,
        ];
        Message::try_from(&buf).expect("parse");
    }
}
