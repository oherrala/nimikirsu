#[macro_use]
extern crate log;
#[macro_use]
extern crate structopt;

extern crate stderrlog;
extern crate kirsulib;

use std::io;

use kirsulib::{parser, pcap::Pcap};

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "nimikirsu", about = "A passive DNS")]
struct Opt {
    /// libpcap capture device
    #[structopt(short = "d", long = "device")]
    device: String,

    /// Verbose mode (-v, -vv, -vvv, etc)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbose: usize,
}

fn main() -> io::Result<()> {
    let opt = Opt::from_args();
    stderrlog::new()
        .modules(vec!["nimikirsu", "kirsulib"])
        .verbosity(opt.verbose)
        .timestamp(stderrlog::Timestamp::Microsecond)
        .init()
        .unwrap();

    debug!("Command line options parsed: {:?}", opt);

    let pcap = Pcap::new(&opt.device)?;
    pcap.set_immediate_mode(true)?;
    pcap.set_snaplen(65535)?;
    pcap.set_promisc(true)?;
    pcap.set_buffer_size(2 * 1024 * 1024)?;

    pcap.activate()?;
    pcap.set_filter("port 53 or port 5353")?;

    for packet in pcap.iter() {
        let frame = match parser::EthernetFrame::try_from(&packet.data) {
            Ok(f) => f,
            Err(err) => {
                warn!("Error parsing EthernetFrame: {}", err);
                continue;
            }
        };
        debug!("{:?}", frame);

        let ipv4_packet = match parser::IPv4Packet::try_from(&frame.payload) {
            Ok(f) => f,
            Err(err) => {
                warn!("Error parsing IPv4Packet: {}", err);
                continue;
            }
        };
        debug!("{:?}", ipv4_packet);

        // UDP Protocol
        if ipv4_packet.protocol == 17 {
            let udp_packet = match parser::UdpPacket::try_from(&ipv4_packet.payload) {
                Ok(f) => f,
                Err(err) => {
                    warn!("Error parsing UdpPacket: {}", err);
                    continue;
                }
            };
            debug!("{:?}", udp_packet);

            if udp_packet.source == 53 || udp_packet.destination == 53 {
                let dns_message = match parser::dns::Message::try_from(&udp_packet.payload) {
                    Ok(f) => f,
                    Err(err) => {
                        warn!("Error parsing DNS Message: {}", err);
                        continue;
                    }
                };
                debug!("{:?}", dns_message);

                #[cfg(feature = "collect")]
                collect::store(&udp_packet.payload)?;

                let qr = match dns_message.header.qr {
                    parser::dns::Qr::Query => "Query",
                    parser::dns::Qr::Response => "Response",
                };

                let questions: Vec<String> = dns_message
                    .question
                    .iter()
                    .map(|q| q.qname.to_string())
                    .collect();
                let answers: Vec<String> = dns_message
                    .answer
                    .iter()
                    .map(|rr| format!("{} = {:?}", rr.name, rr.rdata))
                    .collect();
                println!(
                    "{} {} -> {}: ID: {}, QR: {}, questions: {}, answers: {}",
                    packet.timestamp.to_rfc3339(),
                    ipv4_packet.source,
                    ipv4_packet.destination,
                    dns_message.header.id,
                    qr,
                    questions.join(", "),
                    answers.join(", "),
                );
            }
        }
    }

    Ok(())
}

#[cfg(feature = "collect")]
mod collect {
    extern crate sha1;

    use std::fs;
    use std::io;
    use std::io::Write;

    pub fn store(buf: &[u8]) -> io::Result<()> {
        let mut m = sha1::Sha1::new();
        m.update(buf);
        let name = m.digest().to_string();
        let mut f = fs::File::create(format!("collected/{}.collected", name))?;
        f.write_all(buf)
    }
}
