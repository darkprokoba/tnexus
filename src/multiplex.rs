use std::net::SocketAddr;
use mio::tcp::TcpStream;
use std::collections::BTreeMap;

use tls;

pub enum MR {
    NeedMore,
    Mismatch,
    Match(TcpStream),
}

pub type Multiplexer = Fn(&[u8]) -> MR;

pub fn opaque_forwarder(destination: &str) -> Box<Multiplexer> {
    let destination_addr: SocketAddr = destination.parse()
        .ok().expect("Failed to parse destination enpoint");

    Box::new(move |_| MR::Match(TcpStream::connect(&destination_addr).ok().expect(
            "TODO: outbound failure not handled yet")))
}

pub fn sni_forwarder(default: String, sni_map: BTreeMap<String, String>) -> Box<Multiplexer> {

    Box::new(move |buf: &[u8]| {
        match tls::parse_tls_client_hello(buf) {
            None => MR::NeedMore,
            Some(result) => {
                match result {
                    None => MR::Mismatch,
                    Some(sname) => {
                        let destination: &str = sni_map.get(&sname).unwrap_or(&default);

                        let destination_addr: SocketAddr = destination.parse()
                            .ok().expect("Failed to parse destination enpoint");

                        MR::Match(TcpStream::connect(&destination_addr).ok().expect(
                            "TODO: outbound failure not handled yet"))
                    },
                }
            },
        }
    })
}
