extern crate mio;
extern crate bytes;
extern crate toml;
extern crate openssl;
extern crate hyper;

#[macro_use]
extern crate log;

extern crate env_logger;

use std::io;
use std::net::SocketAddr;
use mio::*;
use mio::tcp::TcpListener;
use mio::util::Slab;

const INVALID: Token = Token(0);
const ACCEPTOR: Token = Token(1);
const FLOW: Token = Token(2);

const OUTMASK: usize = 2147483648; //2 ** 31
const NOTMASK: usize = !OUTMASK;

const EMPTY_BUF: [u8; 0] = []; 

mod api;
mod config;
mod tls;
mod multiplex;
mod flow;

use multiplex::{Multiplexer, MR};

use flow::Flow;

struct Nexus {
    // main server socket (that accepts inbound connections)
    acceptor: TcpListener,

    // token of the acceptor
    token: Token,

    // a list of all inbound and outbound connections
    conns: Slab<Flow>,

    // size for the buffer between the inbound/outbound streams 
    bufsize: usize,

    multiplexer: Box<Multiplexer>,
}

impl Nexus {
    fn new(acceptor: TcpListener, bufsize: usize, multiplexer: Box<Multiplexer>) -> Nexus {
        Nexus {
            acceptor: acceptor,

            // I don't use Token(0) because kqueue will send stuff to Token(0)
            // by default causing really strange behavior. This way, if I see
            // something as Token(0), I know there are kqueue shenanigans
            // going on.
            token: ACCEPTOR,

            // SERVER is Token(1), so start after that
            // we can deal with a max of 126 connections
            conns: Slab::new_starting_at(FLOW, 128),

            bufsize: bufsize,

            multiplexer: multiplexer,
        }
    }

    /// Register Server with the event loop.
    ///
    /// This keeps the registration details neatly tucked away inside of our implementation.
    fn register(&mut self, event_loop: &mut EventLoop<Nexus>) -> io::Result<()> {
        event_loop.register(
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
        
        let inbound_stream = inbound.0;

        let bufsize = self.bufsize;

        match self.conns.insert_with(|token| {
            debug!("Inserting {:?} into slab", token);
            Flow::new(inbound_stream, token, bufsize)
        }) {
            Some(token) => {
                match self.find_connection_by_token(token).inb.register(event_loop) {
                    Ok(_) => {
                        debug!("Registered inbound token {:?}", token);

                        let mr = {
                            self.multiplexer.destination(&EMPTY_BUF)
                        };
                        match mr {
                            MR::Match(outbound) => {
                                //setup outbound immediately!
                                self.find_connection_by_token(token).set_outbound(outbound, bufsize, event_loop);
                            },
                            _ => (),
                        }
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
                let should_stop = match self.conns.get_mut(token) {
                    None => {
                        warn!("Ignoring non-existing readable token: {:?}", token);
                        false
                    },
                    Some(flow) => {
                        if flow.read(inb, self.bufsize, &self.multiplexer, event_loop) {
                            false
                        } else {
                            warn!("Read returned false for token: {:?}", token);
                            true
                        }
                    }
                };
            
                if should_stop {
                    self.stop_flow(token);
                }
            }
        }
    }
}

fn main() {
    env_logger::init().ok().expect("Failed to init logger");

    info!("Starting tnexus...");

    let args = config::get_args();

    let endpoint_addr: SocketAddr = args.listen.parse()
        .ok().expect("Failed to parse server enpoint");

    // Setup the acceptor socket
    let acceptor = TcpListener::bind(&endpoint_addr)
        .ok().expect("Failed to bind server endpoint");

    // Create an event loop
    let mut event_loop = EventLoop::new()
        .ok().expect("Could not initialize MIO event loop");

    let mut nexus = Nexus::new(
        acceptor,
        args.bufsize,
        args.destination);

    // Start listening for incoming connections
    nexus.register(&mut event_loop)
        .ok().expect("Failed to register acceptor in event loop");
    
    // Start handling events
    event_loop.run(&mut nexus)
        .ok().expect("Failed to start event loop");

    info!("Over.");
}
