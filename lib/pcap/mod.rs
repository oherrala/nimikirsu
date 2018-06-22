use libc::{c_int, c_uchar};
use std::ffi::{CStr, CString};
use std::fmt::{self, Write};
use std::io;
use std::mem;
use std::ptr;

use chrono::{DateTime, TimeZone, Utc};

mod bindings;
use self::bindings::*;

pub struct Pcap {
    p: *mut pcap_t,
}

pub struct PcapIter<'a> {
    p: &'a Pcap,
}

impl Pcap {
    pub fn new(source: &str) -> io::Result<Self> {
        trace!("Pcap::new");
        let mut errbuf = vec![0u8; PCAP_ERRBUF_SIZE as usize];
        let source = CString::new(source)?;
        let ret = unsafe { pcap_create(source.as_ptr(), errbuf.as_mut_ptr() as *mut i8) };
        if ret.is_null() {
            let first_nul = errbuf.iter().position(|b| *b == 0u8).unwrap_or(0) + 1;
            let err = CStr::from_bytes_with_nul(&errbuf[..first_nul])
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "cstr from_bytes"))?;
            let errstr = err.to_str()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "cstr to_str"))?;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("pcap_create error {}", errstr),
            ));
        }
        Ok(Pcap { p: ret })
    }

    pub fn get_error(&self) -> io::Result<String> {
        trace!("Pcap::get_error");
        let errbuf = unsafe { pcap_geterr(self.p) };
        let err = unsafe { CStr::from_ptr(errbuf) };
        let errstr = err.to_str()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "cstr to_str"))?;

        Ok(errstr.to_string())
    }

    pub fn set_snaplen(&self, snaplen: usize) -> io::Result<()> {
        trace!("Pcap::set_snaplen({})", snaplen);
        let ret = unsafe { pcap_set_snaplen(self.p, snaplen as c_int) };
        if ret != 0 {
            let err = self.get_error()?;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("pcap_set_snaplen failed: {}", err),
            ));
        }
        Ok(())
    }

    pub fn set_promisc(&self, promisc: bool) -> io::Result<()> {
        trace!("Pcap::set_promisc({})", promisc);
        let promisc = if promisc { 1 } else { 0 };
        let ret = unsafe { pcap_set_promisc(self.p, promisc) };
        if ret != 0 {
            let err = self.get_error()?;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("pcap_set_promisc failed: {}", err),
            ));
        }
        Ok(())
    }

    pub fn set_buffer_size(&self, buffer_size: usize) -> io::Result<()> {
        trace!("Pcap::set_buffer_size({})", buffer_size);
        let ret = unsafe { pcap_set_buffer_size(self.p, buffer_size as c_int) };
        if ret != 0 {
            let err = self.get_error()?;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("pcap_set_buffer_size failed: {}", err),
            ));
        }
        Ok(())
    }

    pub fn set_immediate_mode(&self, immediate: bool) -> io::Result<()> {
        trace!("Pcap::set_immediate_mode({})", immediate);
        let immediate = if immediate { 1 } else { 0 };
        let ret = unsafe { pcap_set_immediate_mode(self.p, immediate) };
        if ret != 0 {
            let err = self.get_error()?;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("pcap_set_buffer_size failed: {}", err),
            ));
        }
        Ok(())
    }

    pub fn set_filter(&self, filter: &str) -> io::Result<()> {
        trace!("Pcap::set_filter({})", filter);
        let program = CString::new(filter)?;
        let mut fp: bpf_program = unsafe { mem::zeroed() };

        let ret = unsafe { pcap_compile(self.p, &mut fp, program.as_ptr(), 0, 0) };
        if ret != 0 {
            let err = self.get_error()?;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("pcap_compile failed: {}", err),
            ));
        }

        let ret = unsafe { pcap_setfilter(self.p, &mut fp) };
        if ret != 0 {
            let err = self.get_error()?;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("pcap_setfilter failed: {}", err),
            ));
        }
        Ok(())
    }

    pub fn activate(&self) -> io::Result<()> {
        trace!("Pcap::activate");
        let ret = unsafe { pcap_activate(self.p) };
        if ret != 0 {
            let err = self.get_error()?;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("pcap_activate failed: {}", err),
            ));
        }
        Ok(())
    }

    pub fn iter(&self) -> PcapIter {
        trace!("Pcap::iter");
        PcapIter { p: self }
    }
}

impl Drop for Pcap {
    fn drop(&mut self) {
        unsafe { pcap_close(self.p) };
    }
}

impl<'a> Iterator for PcapIter<'a> {
    type Item = io::Result<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        trace!("PcapIter::next");
        let mut header: *mut pcap_pkthdr = ptr::null_mut();
        let mut packet: *const c_uchar = ptr::null();

        let ret = unsafe { pcap_next_ex(self.p.p, &mut header, &mut packet) };
        match ret {
            // 0 if packets are being read from a live capture and the timeout
            // expired
            0 => {
                let err = io::Error::new(io::ErrorKind::TimedOut, "timeout on pcap_next_ex()");
                return Some(Err(err));
            }

            // -1 if an error occurred while reading the packet
            -1 => match self.p.get_error() {
                Ok(err) => {
                    let err = io::Error::new(io::ErrorKind::Interrupted, err);
                    return Some(Err(err));
                }
                Err(err) => return Some(Err(err)),
            },

            // -2 if packets are being read from a ``savefile'' and there are no
            // more packets to read from the savefile
            -2 => return None,

            // 1 == success
            _ => (),
        }

        let timeval = unsafe { (*header).ts };
        let ts = Utc.timestamp(timeval.tv_sec, timeval.tv_usec as u32);

        let caplen: usize = unsafe { (*header).caplen } as usize;
        let slice = unsafe { ::std::slice::from_raw_parts(packet, caplen) };

        let packet = Packet {
            timestamp: ts,
            data: Vec::from(slice),
        };

        debug!(
            "Received packet with data (snaplen {}):\n{:?}",
            caplen, packet
        );

        Some(Ok(packet))
    }
}

pub struct Packet {
    pub timestamp: DateTime<Utc>,
    pub data: Vec<u8>,
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let chunk = 32;
        let mut index = 0;
        for large_chunk in self.data.chunks(chunk) {
            let chunks: Vec<String> = large_chunk.chunks(4).map(to_hex).collect();
            writeln!(f, "    {:04}: {}", index, chunks.join(" "))?;
            index += chunk;
        }
        Ok(())
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut buf = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(&mut buf, "{:02x}", byte).expect("write! to String");
    }
    buf
}
