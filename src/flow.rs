use std::io;
use mio::*;
use mio::tcp::TcpStream;
use bytes::buf::{Buf, RingBuf};

use multiplex::{Multiplexer, MR};

use Nexus;

const OUTMASK: usize = 2147483648; //2 ** 31

pub struct Conn {
    // socket
    sock: TcpStream,

    // token used to register the inbound with the event loop
    token: Token,

    // set of events we are interested in
    interest: EventSet,

    // whether the remote peer has half-closed the socket
    // i.e. reading makes no more sense
    dead: bool,
    
    // whether the socket can accept writes right now
    writable: bool,

    // octets in transit
    buf: RingBuf,
}

/// A stateful wrapper around a non-blocking stream. This connection is not
/// the SERVER connection. This connection represents the client connections
/// _accepted_ by the SERVER connection.
pub struct Flow {

    // inbound connection
    pub inb: Conn,
    
    // outbound connection
    out: Option<Conn>,
}

impl Conn {
    fn new(token: Token, sock: TcpStream, bufsize: usize) -> Conn {
        Conn {
            sock: sock,
            token: token,
            interest: EventSet::all(),
            dead: false,
            writable: false,
            buf: RingBuf::new(bufsize),
        }
    }

    /// Register flow interest in read events with the event_loop.
    ///
    /// This will let our connection accept reads starting next event loop tick.
    #[inline]
    pub fn register(&mut self, event_loop: &mut EventLoop<Nexus>)
                -> io::Result<()> {

        event_loop.register(
            &self.sock,
            self.token,
            self.interest, 
            PollOpt::edge())
    }
                
    /// Re-register flow interest in read events with the event_loop.
    #[inline]
    fn reregister(&mut self, event_loop: &mut EventLoop<Nexus>)
                  -> io::Result<()> {

        debug!("Reregistering {:?} for {:?}", self.token, self.interest);
        event_loop.reregister(
            &self.sock, self.token, self.interest, PollOpt::edge()).or_else(|e| {
                error!("Failed to reregister {:?} for {:?} due to {:?}", self.token, self.interest, e);
                Err(e)
            })
    }
}

impl Flow {

    pub fn new(insock: TcpStream, /*ousock: TcpStream,*/ token: Token, bufsize: usize) -> Flow {
        Flow {
            inb: Conn::new(token, insock, bufsize),
            out: None,
        }
    }

    pub fn set_outbound(&mut self, outbound: TcpStream, bufsize: usize, event_loop: &mut EventLoop<Nexus>) -> bool {
    
        let mut out_conn = Conn::new(Token(OUTMASK + self.inb.token.as_usize()), outbound, bufsize);
        out_conn.register(event_loop).ok().expect("TODO: handle registration failure");
        self.out = Some(out_conn);

        self.inb.reregister(event_loop).ok().expect("TODO: handle reregistration failure");

        true
    }

    fn read0(&mut self, bufsize: usize, multiplexer: &Box<Multiplexer>, event_loop: &mut EventLoop<Nexus>) -> bool {
    loop {
        match self.inb.sock.try_read_buf(&mut self.inb.buf) {
            Ok(Some(0)) => {
                debug!("[read0] Successful read of zero bytes (i.e. EOF) from token {:?}", self.inb.token);
                self.inb.dead = true;
                return false;
            },
            Ok(Some(n)) => {
            let remaining = <RingBuf as Buf>::remaining(&self.inb.buf);
                debug!("[read0] Successfully read {} bytes from {:?}, buf size: {}",
                       n, self.inb.token, remaining);
                
                match multiplexer.destination(&self.inb.buf.bytes()) {
                    MR::NeedMore => (), //continue reading
                    MR::Mismatch => {
                        debug!("[read0] Connection unrecognized, aborting!");
                        self.inb.dead = true;
                        return false;
                    },
                    MR::Match(destination) => {
                        return self.set_outbound(destination, bufsize, event_loop);
                    },
                }
                
                if self.inb.buf.is_full() {
                    warn!("[read0] Suspending reads due to buffer full for {:?}", self.inb.token);
                    return false;
                }
            },
            Ok(None) => {
                debug!("Done reading for token {:?}", self.inb.token);
                return true;
            },
            Err(e) => {
                warn!("Read failure {:?} on token {:?}", e, self.inb.token);
                self.inb.dead = true;
                return false;
            }
        }
    }
    }

    /// Handle flow read event from event loop.
    ///
    #[inline]
    pub fn read(&mut self, inbo: bool, bufsize: usize, multiplexer: &Box<Multiplexer>, event_loop: &mut EventLoop<Nexus>) -> bool {

        if inbo {
            match self.out {
                Some(ref mut peer) => read1(&mut self.inb, peer, event_loop),
                None => {
                    self.read0(bufsize, multiplexer, event_loop)
                },
            }
        } else {
            let peer = &mut self.inb;
            match self.out {
                Some(ref mut conn) => read1(conn, peer, event_loop),
                None => panic!("[read] For outbound connections, self.out can never be None")
            }
        }

    }

    #[inline]
    pub fn write(&mut self, inbo: bool, event_loop: &mut EventLoop<Nexus>) -> bool {
        if inbo {
            let conn = &mut self.inb;
            conn.writable = true;
            match self.out {
                Some(ref mut peer) => {
                    write1(conn, peer, event_loop)
                },
                None => {
                    debug!("inbound {:?} is writable, but outbound not ready yet", conn.token);
                    //conn.reregister(event_loop);
                    true
                },
            }
        } else {
            let peer = &mut self.inb;
            match self.out {
                Some(ref mut conn) => {
                    conn.writable = true;
                    write1(conn, peer, event_loop)
                },
                None => panic!("[write] For outbound connections, self.out can never be None")
            }
        }
    }
}

fn read1(conn: &mut Conn, peer: &mut Conn, event_loop: &mut EventLoop<Nexus>) -> bool {
    loop {
        match conn.sock.try_read_buf(&mut conn.buf) {
            Ok(Some(0)) => {
                debug!("Successful read of zero bytes (i.e. EOF) from token {:?}", conn.token);
                conn.dead = true;
                if peer.dead == true && conn.buf.is_empty() && peer.buf.is_empty() {
                    //we're all done:
                    debug!("All done {:?}", conn.token);
                    return false;
                } else {
                    debug!("Suspending reads due to EOF for {:?}", conn.token);
                    conn.interest = conn.interest & !EventSet::readable();
                    conn.reregister(event_loop).ok().expect("TODO: handle re-registration failure");
                    return true;
                }
            },
            Ok(Some(n)) => {
                let remaining = <RingBuf as Buf>::remaining(&conn.buf);
                debug!("Successfully read {} bytes from {:?}, buf size: {}",
                       n, conn.token, remaining);

                if peer.writable {
                    write1(peer, conn, event_loop);
                }
                if conn.buf.is_full() {
                    warn!("Suspending reads due to buffer full for {:?}", conn.token);
                    conn.interest = conn.interest & !EventSet::readable();
                    conn.reregister(event_loop).ok().expect("TODO: handle re-registration failure");
                    return true;
                }
            },
            Ok(None) => {
                debug!("Done reading for token {:?}", conn.token);
                return true;
            },
            Err(e) => {
                warn!("Read failure {:?} on token {:?}", e, conn.token);
                conn.dead = true;
                conn.interest = conn.interest & !EventSet::readable();
                conn.reregister(event_loop).ok().expect("TODO: handle re-registration failure");
                return true;
            }
        }
    }
}

fn write1(conn: &mut Conn, peer: &mut Conn, event_loop: &mut EventLoop<Nexus>) -> bool {
    if peer.buf.is_empty() {
        if conn.dead && conn.buf.is_empty() {
            return false;
        }
    }

    loop {
        
        if peer.buf.is_empty() {
            if !peer.interest.is_readable() {
                peer.interest = peer.interest | EventSet::readable();
                peer.reregister(event_loop).ok().expect("TODO: handle re-registration failure");
            }
            return true;
        }
            
        match conn.sock.try_write_buf(&mut peer.buf) {
            Ok(Some(n)) => {
                debug!("Successfully wrote {} bytes to token {:?}", n, conn.token);
            },
            Ok(None) => {
                debug!("Write not accepted");
                conn.writable = false;
                return true;
            },
            Err(e) => {
                warn!("Write failure {:?} on token {:?}", e, conn.token);
                conn.writable = false;
                return false;
            }
        }
    }
}
