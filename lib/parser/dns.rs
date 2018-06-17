use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;

use untrustended::untrusted::{Input, Reader};
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
        input.read_all(untrustended::Error::ParseError, Self::reader)
    }

    fn reader(input: &mut Reader) -> Result<Self, untrustended::Error> {
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
            let read_so_far: Input = input.get_input_between_marks(mark, input.mark())?;
            trace!("read_so_far: {:?}", read_so_far);
            let r = ResourceRecord::reader(read_so_far, input)?;
            trace!("Read answer {}: {:?}", i + 1, r);
            answer.push(r);
        }

        for i in 0..header.nscount {
            trace!("Reading authority {}/{}", i + 1, header.nscount);
            let read_so_far: Input = input.get_input_between_marks(mark, input.mark())?;
            trace!("read_so_far: {:?}", read_so_far);
            let r = ResourceRecord::reader(read_so_far, input)?;
            trace!("Read authority {}: {:?}", i + 1, r);
            authority.push(r);
        }

        for i in 0..header.arcount {
            trace!("Reading additional {}/{}", i + 1, header.arcount);
            let read_so_far: Input = input.get_input_between_marks(mark, input.mark())?;
            trace!("read_so_far: {:?}", read_so_far);
            let r = ResourceRecord::reader(read_so_far, input)?;
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
        let z = bitfield & 0b0000_0000_0111_0000;
        if z != 0 {
            warn!("DNS Header Z must be zero: z = {}", z);
            return Err(untrustended::Error::ParseError);
        }

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
    /// TYPE two octets containing one of the RR type codes.  This field specifies the meaning of the data in the RDATA field.
    /// CLASS two octets which specify the class of the data in the RDATA field.
    /// TTL a 32 bit unsigned integer that specifies the time interval (in seconds) that the resource record may be cached before it should be discarded.  Zero values are interpreted to mean that the RR can only be used for the transaction in progress, and should not be cached.
    pub ttl: u32,
    /// RDLENGTH an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    /// RDATA a variable length string of octets that describes the resource.  The format of this information varies according to the TYPE and CLASS of the resource record. For example, the if the TYPE is A and the CLASS is IN, the RDATA field is a 4 octet ARPA Internet address.
    pub rdata: RData,
}

#[derive(Debug)]
pub enum RData {
    IPv4Addr(Ipv4Addr),
    IPv6Addr(Ipv6Addr),
    Ns(String),
    Cname(String),
    Ptr(String),
    Mx((u16, String)),
    UnhandledType(u16),
}

impl ResourceRecord {
    fn reader(read_so_far: Input, input: &mut Reader) -> Result<Self, untrustended::Error> {
        trace!("ResourceRecord::reader");
        let name = read_name(read_so_far, input)?;
        let rr_type = input.read_u16be()?;

        let class = input.read_u16be()?;
        if class != 1 {
            warn!("Only IN CLASS supported in ResourceRecord");
            return Err(untrustended::Error::ParseError);
        }

        let ttl = input.read_u32be()?;
        let rdlength = input.read_u16be()?;
        let rdata_raw = input.skip_and_get_input(rdlength as usize)?;
        // FIXME: Don't use Reader::new
        let mut rdata_reader = Reader::new(rdata_raw);

        let rdata = match rr_type {
            // A     1 a host address
            1 => RData::IPv4Addr(rdata_reader.read_ipv4addr()?),
            // NS    2 an authoritative name server
            2 => RData::Ns(read_name(read_so_far, &mut rdata_reader)?),
            // MD    3 a mail destination (Obsolete - use MX)
            // MF    4 a mail forwarder (Obsolete - use MX)
            // CNAME 5 the canonical name for an alias
            5 => RData::Cname(read_name(read_so_far, &mut rdata_reader)?),
            // SOA   6 marks the start of a zone of authority
            // MB    7 a mailbox domain name (EXPERIMENTAL)
            // MG    8 a mail group member (EXPERIMENTAL)
            // MR    9 a mail rename domain name (EXPERIMENTAL)
            // NULL  10 a null RR (EXPERIMENTAL)
            // WKS   11 a well known service description
            // PTR   12 a domain name pointer
            12 => RData::Ptr(read_name(read_so_far, &mut rdata_reader)?),
            // HINFO 13 host information
            // MINFO 14 mailbox or mail list information
            // MX    15 mail exchange
            15 => {
                let preference = rdata_reader.read_u16be()?;
                let exchange = read_name(read_so_far, &mut rdata_reader)?;
                RData::Mx((preference, exchange))
            }
            // AAAA 28  The AAAA resource record type is a record specific to
            // the Internet class that stores a single IPv6 address.
            // https://tools.ietf.org/html/rfc3596
            28 => RData::IPv6Addr(rdata_reader.read_ipv6addr()?),
            // TXT   16 text strings
            n => RData::UnhandledType(n),
        };

        Ok(ResourceRecord { name, ttl, rdata })
    }
}

/// a domain name represented as a sequence of labels, where each label consists
/// of a length octet followed by that number of octets.  The domain name
/// terminates with the zero length octet for the null label of the root.  Note
/// that this field may be an odd number of octets; no padding is used.
fn read_name(read_so_far: Input, input: &mut Reader) -> Result<String, untrustended::Error> {
    trace!("read_name");
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
            // FIXME: Don't use Reader::new
            let mut reader = Reader::new(read_so_far);

            let mark = reader.mark();
            reader.skip(offset)?;
            // This ensures we can only look the past labels
            let read_so_far = reader.get_input_between_marks(mark, reader.mark())?;

            let label = read_name(read_so_far, &mut reader)?;
            trace!("Read compressed label(s) \"{}\"", label);
            name_len += label.len();
            label
        } else {
            if len > 63 {
                warn!("Invalid DNS label length: {}", len);
                return Err(untrustended::Error::ParseError);
            }

            let bytes = input.read_bytes_less_safe(len as usize)?;
            if !bytes.iter().all(|l| char::from(*l).is_ascii()) {
                let label: Vec<char> = bytes.iter().map(|l| char::from(*l)).collect();
                warn!("Invalid DNS label: {:?}", label);
                return Err(untrustended::Error::ParseError);
            }

            let label = match str::from_utf8(bytes) {
                Ok(l) => l,
                Err(err) => {
                    warn!("Converting to string failed for {:?}: {}", bytes, err);
                    return Err(untrustended::Error::ParseError);
                }
            };
            trace!("Read label \"{}\"", label);
            name_len += usize::from(len);
            label.to_string()
        };

        name.push(label);
        if name_len > 255 {
            warn!("Too long DNS name: {}", name.len());
            return Err(untrustended::Error::ParseError);
        }

        if offset > 0 {
            break;
        }
    }

    if name.is_empty() {
        warn!("Couldn't parse DNS name");
        return Err(untrustended::Error::ParseError);
    }

    let name = name.join(".");
    debug!("Reading name done: \"{}\"", name);
    Ok(name)
}
