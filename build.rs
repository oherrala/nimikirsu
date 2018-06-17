extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=pcap");
    let bindings = bindgen::Builder::default()
        .header("lib/pcap/pcap_wrapper.h")
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("pcap_bindings.rs"))
        .expect("Couldn't write bindings!");
}
