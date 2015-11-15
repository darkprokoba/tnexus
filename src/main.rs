extern crate mio;

#[macro_use]
extern crate log;

extern crate env_logger;

use std::io;
use std::net::SocketAddr;
use mio::*;
use mio::tcp::{TcpListener, TcpStream};
use mio::util::Slab;
use mio::buf::RingBuf;

const ENDPOINT: &'static str = "127.0.0.1:6666";
const DESTINATION: &'static str = "127.0.0.1:80";

//const BUF_SIZE: usize = 524288; //131072;
//const BUF_SIZE: usize = 8388608;
const BUF_SIZE: usize = 1048576;

const INVALID: Token = Token(0);
const ACCEPTOR: Token = Token(1);
const FLOW: Token = Token(2);

const OUTMASK: usize = 2147483648; //2 ** 31
const NOTMASK: usize = !OUTMASK;

struct Conn {
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
struct Flow {

    // inbound connection
    inb: Conn,

    // outbound connection
    out: Conn,
}

struct Nexus {
    // main server socket (that accepts inbound connections)
    acceptor: TcpListener,

    // token of the acceptor
    token: Token,

    // a list of all inbound and outbound connections
    conns: Slab<Flow>,
}

impl Conn {
    fn new(token: Token, sock: TcpStream) -> Conn {
        Conn {
            sock: sock,
            token: token,
            interest: EventSet::all(),
            dead: false,
            writable: false,
            buf: RingBuf::new(BUF_SIZE),
        }
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

    fn new(insock: TcpStream, ousock: TcpStream, token: Token) -> Flow {
        Flow {
            inb: Conn::new(token, insock),
            out: Conn::new(Token(OUTMASK + token.as_usize()), ousock),
        }
    }

    /// Register flow interest in read events with the event_loop.
    ///
    /// This will let our connection accept reads starting next event loop tick.
    fn register(&mut self, event_loop: &mut EventLoop<Nexus>)
                -> io::Result<()> {

        event_loop.register_opt(
            &self.inb.sock,
            self.inb.token,
            self.inb.interest, 
            PollOpt::edge()).and_then(|_|
        event_loop.register_opt(
            &self.out.sock,
            self.out.token,
            self.out.interest, 
            PollOpt::edge())).
        or_else(|e| {
            error!("Failed to register {:?} due to {:?}", self.inb.token, e);
            Err(e)
        })
    }

    /// Handle flow read event from event loop.
    ///
    #[inline]
    fn read(&mut self, inbo: bool, event_loop: &mut EventLoop<Nexus>) -> bool {

        let conn;
        let peer;
        if inbo {
            conn = &mut self.inb;
            peer = &mut self.out;
        } else {
            conn = &mut self.out;
            peer = &mut self.inb;
        }

        read1(conn, peer, event_loop)
    }

    #[inline]
    fn write(&mut self, inbo: bool, event_loop: &mut EventLoop<Nexus>) -> bool {
        let conn;
        let peer;
        if inbo {
            conn = &mut self.inb;
            peer = &mut self.out;
        } else {
            conn = &mut self.out;
            peer = &mut self.inb;
        }

        conn.writable = true;

        write1(conn, peer, event_loop)
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
                    conn.reregister(event_loop);
                    return true;
                }
            },
            Ok(Some(n)) => {
                debug!("Successfully read {} bytes from {:?}, buf size: {}",
                       n, conn.token, <RingBuf as Buf>::remaining(&conn.buf));
                if peer.writable {
                    write1(peer, conn, event_loop);
                }
                if conn.buf.is_full() {
                    warn!("Suspending reads due to buffer full for {:?}", conn.token);
                    conn.interest = conn.interest & !EventSet::readable();
                    conn.reregister(event_loop);
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
                conn.reregister(event_loop);
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
                peer.reregister(event_loop);
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

impl Nexus {
    fn new(acceptor: TcpListener) -> Nexus {
        Nexus {
            acceptor: acceptor,

            // I don't use Token(0) because kqueue will send stuff to Token(0)
            // by default causing really strange behavior. This way, if I see
            // something as Token(0), I know there are kqueue shenanigans
            // going on.
            token: ACCEPTOR,

            // SERVER is Token(1), so start after that
            // we can deal with a max of 126 connections
            conns: Slab::new_starting_at(FLOW, 128)
        }
    }

    /// Register Server with the event loop.
    ///
    /// This keeps the registration details neatly tucked away inside of our implementation.
    fn register(&mut self, event_loop: &mut EventLoop<Nexus>) -> io::Result<()> {
        event_loop.register_opt(
            &self.acceptor,
            self.token,
            EventSet::readable(),
            PollOpt::edge(), // | PollOpt::oneshot()
        ).or_else(|e| {
            error!("Failed to register server {:?}, {:?}", self.token, e);
            Err(e)
        })
    }

    /// Accept a _new_ client connection.
    ///
    /// The server will keep track of the new connection and forward any events from the event loop
    /// to this connection.
    fn accept(&mut self, event_loop: &mut EventLoop<Nexus>) {
        debug!("tnexus accepting new socket(s)");

        loop {
        // Log an error if there is no socket, but otherwise move on so we do not tear down the
        // entire server.
        let inbound = match self.acceptor.accept() {
            Ok(s) => {
                match s {
                    Some(sock) => sock,
                    None => {
                        debug!("No more new sockets");
                        return;
                    }
                }
            },
            Err(e) => {
                error!("Failed to accept new socket, {:?}", e);
                return;
            }
        };

        let dst_addr: SocketAddr = DESTINATION.parse()
            .ok().expect("Failed to parse destination endpoint");

        let outbound = TcpStream::connect(&dst_addr).ok().expect("outbound failure not handled yet");

        match self.conns.insert_with(|token| {
            debug!("Inserting {:?} into slab", token);
            Flow::new(inbound, outbound, token)
        }) {
            Some(token) => {
                match self.find_connection_by_token(token).register(event_loop) {
                    Ok(_) => {
                        debug!("Registered inbound token {:?}", token);
                        
                    },
                    Err(e) => {
                        error!("Failed to register inbound {:?} connection with event loop, {:?}", token, e);
                        self.conns.remove(token);
                    }
                }
            },
            None => {
                // If we fail to insert, the socks will go out of scope and be dropped.
                error!("Failed to insert into slab");
            }
        };

        }
    }

    fn stop_flow(&mut self, token: Token) {
        debug!("Stopping flow {:?}", token);
        self.conns.remove(token);
    }

    /// Find a connection in the slab using the given token.
    fn find_connection_by_token<'a>(&'a mut self, token: Token) -> &'a mut Flow {
        &mut self.conns[token]
    }

    /*
    fn with_flow<F, R>(&mut self, token: Token, mut closure: F) -> Option<R>
        where F: FnMut(&mut Flow) -> R {

        match self.conns.get_mut(token) {
            None => {
                warn!("Token not found: {:?}", token);
                None
            },
            Some(flow) => {
                Some(closure(flow))
            }
        }
    }
    */
}

impl Handler for Nexus {
    type Timeout = ();
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Nexus>, _token: Token, events: EventSet) {
        assert!(_token != INVALID, "[BUG]: Received event for Token(0)");

        let tokval = _token.as_usize();
        let inb = tokval & OUTMASK == 0;
        let token = Token(tokval & NOTMASK);
        
        debug!("READY {:X} {} {:?} {:?}", tokval, inb, token, events);

        if events.is_error() {
            warn!("Final event {:?} for token {:X}", events, tokval);
        }

        // We never expect a write event for our `Server` token . A write event for any other token
        // should be handed off to that connection.
        if events.is_writable() {
            debug!("Write event for {:X}", tokval);
            assert!(self.token != token, "Received writable event for Server");

            let write_result = match self.conns.get_mut(token) {
                None => {
                    warn!("Unknown token {:X}", tokval);
                    return;
                },
                Some(flow) => {
                    flow.write(inb, event_loop)
                }
            };

            if !write_result {
                self.stop_flow(token);
                return;
            }
        }
        
        // A read event for our `Server` token means we are establishing a new connection. A read
        // event for any other token should be handed off to that connection.
        if events.is_readable() {
            if ACCEPTOR == token {
                self.accept(event_loop);
            } else {
                if !self.find_connection_by_token(token).read(inb, event_loop) {
                    self.stop_flow(token);
                }
            }
        }
    }
}

fn main() {
    env_logger::init().ok().expect("Failed to init logger");

    info!("Starting tnexus...");
    
    let endpoint_addr: SocketAddr = ENDPOINT.parse()
        .ok().expect("Failed to parse server enpoint");

    // Setup the acceptor socket
    let acceptor = TcpListener::bind(&endpoint_addr)
        .ok().expect("Failed to bind server endpoint");

    // Create an event loop
    let mut event_loop = EventLoop::new()
        .ok().expect("Could not initialize MIO event loop");

    let mut nexus = Nexus::new(acceptor);

    // Start listening for incoming connections
    nexus.register(&mut event_loop)
        .ok().expect("Failed to register acceptor in event loop");
    
    // Start handling events
    event_loop.run(&mut nexus)
        .ok().expect("Failed to start event loop");

    info!("Over.");
}
