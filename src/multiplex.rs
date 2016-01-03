use std::net::SocketAddr;
use mio::tcp::TcpStream;
use std::collections::HashMap;

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

pub fn sni_forwarder() -> Box<Multiplexer> {

    let default = "127.0.0.1:443";
    let mut sni_map = HashMap::new();
    sni_map.insert("www.redhat.com", "23.45.109.223:443");
    sni_map.insert("news.ycombinator.com", "198.41.191.47:443");

    Box::new(move |buf: &[u8]| {
        match tls::parse_tls_client_hello(buf) {
            None => MR::NeedMore,
            Some(result) => {
                match result {
                    None => MR::Mismatch,
                    Some(sname) => {
                        let s: &str = &sname[..]; 
                        let destination: &str = sni_map.get(&s).unwrap_or(&default);

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
