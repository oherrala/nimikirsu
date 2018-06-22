#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate kirsulib;

use kirsulib::parser::IPv4Packet;

fuzz_target!(|data: &[u8]| {
    let _ip_packet = IPv4Packet::try_from(data);
});
