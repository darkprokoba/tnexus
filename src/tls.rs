const SSL_CONTENTTYPE_HANDSHAKE: u8 = 22;
const SSL_HANDSHAKE_CLIENTHELLO: u8 = 1;
const SSL_EXTENSION_SNI: usize = 0;

/// Extracts the first SNI (Server Name Indication) from a TLS client hello message.
///
/// More stuff.
pub fn parse_tls_client_hello(buf: &[u8]) -> Option<Option<String>> {
    let buf_len = buf.len();
    if buf_len < 1 {
        return None; //want more bytes
    }
    
    if buf[0] != SSL_CONTENTTYPE_HANDSHAKE {
        debug!("Not a handshake");
        return Some(None); //we know it's not tls
    }
    
    if buf_len < 3 {
        return None; //want more bytes
    }
    
    if buf[1] < 3 || buf[2] < 1 {
        debug!("Bad SSL protocol version {}.{}", buf[1], buf[2]);
        return Some(None);
    }

    if buf_len < 6 {
        return None; //want more bytes
    }
    
    if buf[5] != SSL_HANDSHAKE_CLIENTHELLO {
        debug!("Not a CLIENTHELLO {}", buf[3]);
        return Some(None); //we know it's not clienthello
    }
    
    let msglen = 5 + (buf[3] as usize) * 256 + (buf[4] as usize);
    
    if buf_len < msglen {
        return None; //want more bytes (entire handshake)
    }
    
    let mut idx = 43usize;
    if idx >= buf_len - 1 {
        debug!("ClientHello is too short {}", buf_len);
        return Some(None)
    }
    
    idx += 1 + buf[idx] as usize; //skip sessionid

    if idx >= buf_len - 2 {
        debug!("Reached message end after sessionid.");
        return Some(None)
    }

    idx += 2 + (buf[idx] as usize) * 256 + (buf[idx + 1] as usize); //skip cipher suites

    if idx >= buf_len - 1 {
        debug!("Message too short while reading compression methods length");
        return Some(None)
    }

    idx += 1 + (buf[idx] as usize); //compression methods
    
    if idx >= buf_len - 2 {
        debug!("Reached message end before extension section length index");
        return Some(None)
    }
    
    let extend = 2 + idx + (buf[idx] as usize) * 256 + (buf[idx + 1] as usize);
    
    idx += 2;
    loop {
        if idx < extend - 4 && idx < buf_len - 4 {
            let extype = (buf[idx] as usize) * 256 + (buf[idx + 1] as usize);
            let extlen = (buf[idx + 2] as usize) * 256 + (buf[idx + 3] as usize);
            if extype == SSL_EXTENSION_SNI {
                let sniend = 4 + idx + extlen;
                if sniend <= buf_len {
                    //debug!("extracting {:?} {} {}", buf, idx + 4, sniend);
                    let sni = &buf[idx + 9 .. sniend];
                    let vec: Vec<u8> = sni.iter().map(|c| *c).collect();
                    //debug!("extracted sni '{:?}'", vec);
                    return match String::from_utf8(vec) {
                        Ok(name) => Some(Some(name)),
                        _ => None,
                    };
                } else {
                    debug!("Bad sni end {}", sniend);
                }
            }
            
            //next extension:
            idx += 4 + extlen;
        } else {
            debug!("error while parsing extension info");
            break;
        }
    }

    Some(None)
}
