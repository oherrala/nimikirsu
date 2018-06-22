#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate kirsulib;

use kirsulib::parser::UdpPacket;

fuzz_target!(|data: &[u8]| {
    let _udp_packet = UdpPacket::try_from(data);
});
