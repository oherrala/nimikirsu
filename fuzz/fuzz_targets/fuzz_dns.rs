#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate kirsulib;

use kirsulib::parser::dns::Message;

fuzz_target!(|data: &[u8]| {
    let _dns_message = Message::try_from(data);
});
