#[macro_use]
extern crate log;

extern crate env_logger;
extern crate kirsulib;

use std::io;

use kirsulib::{parser, pcap::Pcap};

fn main() -> io::Result<()> {
    env_logger::init();
    info!("Main");

    let pcap = Pcap::new("en0")?;
    pcap.set_snaplen(65535)?;
    pcap.set_promisc(true)?;
    pcap.set_buffer_size(2 * 1024 * 1024)?;
    pcap.set_immediate_mode(true)?;

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
