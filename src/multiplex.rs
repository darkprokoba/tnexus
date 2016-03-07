use std::net::SocketAddr;
use std::collections::BTreeMap;
use std::fmt::Debug;

use tls;

pub enum MR {
    NeedMore,
    Mismatch,
    Match(SocketAddr),
}

pub trait Multiplexer : Debug {
    fn destination(&self, &[u8]) -> MR;
}

#[derive(Debug)]
pub struct FixedPlexer {
    destination_addr: SocketAddr,
}

#[derive(Debug)]
pub struct SniPlexer {
    default_addr: String,
    sni_map: BTreeMap<String, String>
}

impl FixedPlexer {
    pub fn new(addr: &str) -> FixedPlexer {
        FixedPlexer {
            destination_addr: addr.parse().ok().expect("Failed to parse destination enpoint")
        }
    }
}

impl Multiplexer for FixedPlexer {
    fn destination(&self, _buf: &[u8]) -> MR {
        MR::Match(self.destination_addr)
    }
}

impl SniPlexer {
    pub fn new(default_addr: &str, sni_map: BTreeMap<String, String>) -> SniPlexer {
        SniPlexer {
            default_addr: default_addr.to_string(),
            sni_map: sni_map,
        }
    }
}

impl Multiplexer for SniPlexer {
    fn destination(&self, buf: &[u8]) -> MR {
        match tls::parse_tls_client_hello(buf) {
            None => MR::NeedMore,
            Some(result) => {
                match result {
                    None => MR::Mismatch,
                    Some(sname) => {
                        let destination: &str = self.sni_map.get(&sname).unwrap_or(&self.default_addr);

                        let destination_addr: SocketAddr = destination.parse()
                            .ok().expect("Failed to parse destination enpoint");

                        MR::Match(destination_addr)
                    },
                }
            },
        }
    }
}
