#[macro_use]
extern crate log;
#[macro_use]
extern crate structopt;

extern crate kirsulib;
extern crate nix;
extern crate privdrop;
extern crate stderrlog;

use std::io;
use std::path::PathBuf;
use std::process;

use nix::unistd;
use structopt::StructOpt;

use kirsulib::{parser, parser::dns, pcap::Pcap};

#[derive(Debug, StructOpt)]
#[structopt(name = "nimikirsu", about = "A passive DNS")]
struct Opt {
    /// libpcap capture device
    #[structopt(short = "d", long = "device")]
    device: String,

    /// Verbose mode (-v, -vv, -vvv, etc)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbose: usize,

    /// setuid user
    #[structopt(long = "user")]
    setuid_user: Option<String>,

    /// chroot path
    #[structopt(long = "chroot", parse(from_os_str))]
    chroot_dir: Option<PathBuf>,
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

    if unistd::geteuid() == 0 {
        let mut pd = privdrop::PrivDrop::default();
        if let Some(user) = opt.setuid_user {
            pd = pd.user(&user).unwrap_or_else(|e| {
                eprintln!("Failed to drop privileges: {}", e);
                process::exit(1);
            });
        }
        if let Some(chroot) = opt.chroot_dir {
            pd = pd.chroot(chroot);
        }
        pd.apply().unwrap_or_else(|e| {
            eprintln!("Failed to drop privileges: {}", e);
            process::exit(1);
        });
    } else {
        if let Some(user) = opt.setuid_user {
            eprintln!("Cannot setuid to {}: Not running as root", user);
            process::exit(1);
        }
        if let Some(chroot) = opt.chroot_dir {
            eprintln!("Cannot chroot to {:?}: Not running as root", chroot);
            process::exit(1);
        }
    }

    for packet_or_err in pcap.iter() {
        let raw_packet = match packet_or_err {
            Ok(packet) => packet,
            Err(err) => panic!("Error from Pcap::Iterator: {}", err),
        };

        let packet = match parser::ParsedPacket::try_from(&raw_packet.data) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let timestamp = raw_packet.timestamp;

        if packet.source.port() == 53
            || packet.source.port() == 5353
            || packet.destination.port() == 53
            || packet.destination.port() == 5353
        {
            let dns_message = match dns::Message::try_from(packet.payload.as_slice_less_safe()) {
                Ok(f) => f,
                Err(err) => {
                    panic!("Error parsing DNS Message: {}", err);
                    // continue;
                }
            };
            debug!("{:?}", dns_message);

            #[cfg(feature = "collect")]
            collect::store(&udp_packet.payload)?;

            use parser::dns::{Qr, Rcode};
            let qr = match dns_message.header.qr {
                Qr::Query => "Query",
                Qr::Response => match dns_message.header.rcode {
                    Rcode::NoError => "Response",
                    Rcode::FormatError => "Response(FormatError)",
                    Rcode::ServerFailure => "Response(ServerFailure)",
                    Rcode::NameError => "Response(NameError)",
                    Rcode::NotImplemented => "Response(NotImplemented)",
                    Rcode::Refused => "Response(Refused)",
                    Rcode::FutureUse(_) => "Response(FutureUse)",
                },
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
                timestamp.to_rfc3339(),
                packet.source,
                packet.destination,
                dns_message.header.id,
                qr,
                questions.join(", "),
                answers.join(", "),
            );
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
