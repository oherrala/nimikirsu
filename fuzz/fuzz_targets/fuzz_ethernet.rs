#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate kirsulib;

use kirsulib::parser::EthernetFrame;

fuzz_target!(|data: &[u8]| {
    let _eth_frame = EthernetFrame::try_from(data);
});
