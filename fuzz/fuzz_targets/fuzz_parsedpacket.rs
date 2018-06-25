#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate kirsulib;

use kirsulib::parser::ParsedPacket;

fuzz_target!(|data: &[u8]| {
    let _packet = ParsedPacket::try_from(data);
});
