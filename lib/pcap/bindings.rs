#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

// We don't care about generated code's clippy nags
#![cfg_attr(feature = "cargo-clippy", allow(clippy))]

include!(concat!(env!("OUT_DIR"), "/pcap_bindings.rs"));
