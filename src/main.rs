extern crate mio;

#[macro_use]
extern crate log;

extern crate env_logger;

use std::io;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use mio::*;
use mio::tcp::{TcpListener, TcpStream};
use mio::util::Slab;
use mio::buf::RingBuf;

const ENDPOINT: &'static str = "127.0.0.1:6666";
const DESTINATION: &'static str = "127.0.0.1:22";

const BUF_SIZE: usize = 131072;
const INVALID: Token = Token(0);
const ACCEPTOR: Token = Token(1);
const FLOW: Token = Token(2);

#[derive(Debug)]
enum BufState {
    Empty, //read interest, no peer write interest
    Data,  //read interest, peer write interest
    Full   //no read interest, peer write interest
}

/// A stateful wrapper around a non-blocking stream. This connection is not
/// the SERVER connection. This connection represents the client connections
/// _accepted_ by the SERVER connection.
struct Flow {
    // handle to the accepted inbound socket
    sock: TcpStream,

    // token used to register with the event loop
    token: Token,

    peer_token: Token,

    // set of events we are interested in
    interest: EventSet,

    // octets in transit
    buf: RingBuf,
}

struct Nexus {
    // main server socket (that accepts inbound connections)
    acceptor: TcpListener,

    // token of our acceptor.
    token: Token,
    
    // a list of all inbound and outbound connections
    conns: Slab<Flow>,
}

impl Flow {

    fn new_inflow(sock: TcpStream, token: Token) -> Flow {
        Flow {
            sock: sock,
            token: token,
            peer_token: INVALID,
            interest: EventSet::readable() | EventSet::hup() | EventSet::error(),
            buf: RingBuf::new(BUF_SIZE)
        }
    }
    
    fn new(sock: TcpStream, token: Token, peer_token: Token) -> Flow {
        Flow {
            sock: sock,
            token: token,
            peer_token: peer_token,
            interest: EventSet::readable() | EventSet::hup() | EventSet::error(),
            buf: RingBuf::new(BUF_SIZE)
        }
    }
    
    /// Register flow interest in read events with the event_loop.
    ///
    /// This will let our connection accept reads starting next event loop tick.
    fn register(&mut self, event_loop: &mut EventLoop<Nexus>) -> io::Result<()> {
        event_loop.register_opt(
            &self.sock,
            self.token,
            self.interest, 
            PollOpt::edge() | PollOpt::oneshot()
        ).or_else(|e| {
            error!("Failed to reregister {:?}, {:?}", self.token, e);
            Err(e)
        })
    }

    /// Re-register flow interest in read events with the event_loop.
    fn reregister(&mut self, event_loop: &mut EventLoop<Nexus>) -> io::Result<()> {
        debug!("Reregistering {:?} for {:?}", self.token, self.interest);
        event_loop.reregister(
            &self.sock,
            self.token,
            self.interest,
            PollOpt::edge() | PollOpt::oneshot()
        ).or_else(|e| {
            error!("Failed to reregister {:?}, {:?}", self.token, e);
            Err(e)
        })
    }

    // when a flow reads successfully, adjust it's 'read' interest,
    // and calculate advice for the peer writer.
    fn read_interest(&mut self) -> BufState {
        if self.buf.is_empty() {
            self.interest = self.interest | EventSet::readable();
            BufState::Empty
        } else if self.buf.is_full() {
            self.interest = self.interest & !EventSet::readable();
            debug!("(our read buf full) Suspended reads {:?} for token {:?}",
                   self.interest, self.token);
            BufState::Full
        } else {
            self.interest = self.interest | EventSet::readable();
            BufState::Data
        }
    }

    // a peer flow has read successfully.
    // decide if we should be interested in writing
    // (we will be if the peer's buf is not empty)
    fn peer_read_interest(&mut self, state: BufState) {
        match state {
            BufState::Empty => {
                self.interest = self.interest & !EventSet::writable();
            },
            BufState::Data => {
                self.interest = self.interest | EventSet::writable();
            },
            BufState::Full => {
                self.interest = self.interest | EventSet::writable();
            },
        }
    }

    // we have just finished writing, adjust our write interest.
    // we're always interested in writing.
    // calculate advice for our peer reader (peer should stop reading if we wrote zero bytes).
    fn write_interest(&mut self, written: usize) -> BufState {
        //self.interest = self.interest | EventSet::writable();

        match written {
            0 => {
                //kernel write buffer is full
                //we always want write notifications
                //but we should signal the peer to stop reading!
                BufState::Full
            }
            _ => {
                //kernel accepted some octets for writing
                //we always want write notifications
                //the peer should continue reading
                BufState::Data
            }
        }
    }

    // our peer has just finished writing,
    // decide if we should keep reading based on peer's advice.
    // (we should keep reading unless the peer write buf is full)
    fn peer_write_interest(&mut self, state: BufState) {
        match state {
            BufState::Full => {
                //self.interest = self.interest & !EventSet::readable();
                debug!("(peer write buf full) Suspended reads {:?} for token {:?}",
                       self.interest, self.token);
            },

            _ => {
                self.interest = self.interest | EventSet::readable();
            }
        }
    }
    
    /// Handle flow read event from event loop.
    ///
    fn read_flow(&mut self, token: Token) -> io::Result<BufState> {
        match self.sock.try_read_buf(&mut self.buf) {
            Ok(Some(0)) => {
                debug!("Successful read of zero bytes from token {:?}", token);
                Err(Error::new(ErrorKind::Other, "Could not pop send queue"))
            },
            Ok(Some(n)) => {
                debug!("Successfully read {} bytes from {:?}, buf size: {}",
                       n, token, <RingBuf as Buf>::remaining(&self.buf));

                Ok(self.read_interest())
            },
            Ok(None) => {
                debug!("Spurious event for token {:?}", token);
                Ok(self.read_interest())
            },
            Err(e) => {
                warn!("Read failure {:?} on token {:?}", e, token);
                Err(e)
            }
        }
    }

    /// Handle a writable event from the event loop.
    ///
    fn write_flow(&mut self, token: Token, peer_buf: &mut RingBuf) -> io::Result<BufState> {
        if peer_buf.is_empty() {
            warn!("Peer read buf is empty, skip writing for token {:?}", token);
            // do not spam us with write events, until peer produces something in their read buffer:
            self.interest = self.interest & !EventSet::writable();
            Ok(BufState::Data)
        } else {
            match self.sock.try_write_buf(peer_buf) {
                Ok(Some(n)) => {
                    debug!("Wrote {} bytes to token {:?}", n, token);
                    Ok(self.write_interest(n))
                },
                Ok(None) => {
                    debug!("Write not accepted");
                    Ok(self.write_interest(0))
                },
                Err(e) => {
                    warn!("Write failure {:?} on token {:?}", e, token);
                    Err(e)
                }
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
            PollOpt::edge() | PollOpt::oneshot()
        ).or_else(|e| {
            error!("Failed to register server {:?}, {:?}", self.token, e);
            Err(e)
        })
    }

    /// Register Server with the event loop.
    ///
    /// This keeps the registration details neatly tucked away inside of our implementation.
    fn reregister(&mut self, event_loop: &mut EventLoop<Nexus>) {
        event_loop.reregister(
            &self.acceptor,
            self.token,
            EventSet::readable(),
            PollOpt::edge() | PollOpt::oneshot()
        ).unwrap_or_else(|e| {
            error!("Failed to reregister nexus {:?}, {:?}", self.token, e);
            event_loop.shutdown();
        })
    }

    /// Accept a _new_ client connection.
    ///
    /// The server will keep track of the new connection and forward any events from the event loop
    /// to this connection.
    fn accept(&mut self, event_loop: &mut EventLoop<Nexus>) {
        debug!("server accepting new socket");

        // Log an error if there is no socket, but otherwise move on so we do not tear down the
        // entire server.
        let inbound = match self.acceptor.accept() {
            Ok(s) => {
                match s {
                    Some(sock) => sock,
                    None => {
                        error!("Failed to accept new socket");
                        self.reregister(event_loop);
                        return;
                    }
                }
            },
            Err(e) => {
                error!("Failed to accept new socket, {:?}", e);
                self.reregister(event_loop);
                return;
            }
        };

        // `Slab#insert_with` is a wrapper around `Slab#insert`. I like `#insert_with` because I
        // make the `Token` required for creating a new connection.
        //
        // `Slab#insert` returns the index where the connection was inserted. Remember that in mio,
        // the Slab is actually defined as `pub type Slab<T> = ::slab::Slab<T, ::Token>;`. Token is
        // just a tuple struct around `usize` and Token implemented `::slab::Index` trait. So,
        // every insert into the connection slab will return a new token needed to register with
        // the event loop. Fancy...


        match self.conns.insert_with(|token| {
            debug!("registering inbound {:?} with event loop", token);
            Flow::new_inflow(inbound, token)
        }) {
            Some(token) => {
                // If we successfully insert, then register our connection.
                //let ref mut inflow = {
                //    self.find_connection_by_token(token);
                //};
                match self.find_connection_by_token(token).register(event_loop) {
                    Ok(_) => {
                        info!("Registered inbound token {:?}", token);
                        // start and register the outbound connection:
                        let dst_addr: SocketAddr = DESTINATION.parse()
                            .ok().expect("Failed to parse destination endpoint");

                        let outbound = TcpStream::connect(&dst_addr).unwrap();
                        
                        match self.conns.insert_with(|outoken| {
                            debug!("registering outbound token {:?} with event loop", outoken);
                            Flow::new(outbound, outoken, token)
                        }) {
                            Some(outoken) => {
                                match self.find_connection_by_token(outoken).register(event_loop) {
                                    Ok(_) => {
                                        self.find_connection_by_token(token).peer_token = outoken;
                                        debug!("Registered outbound token {:?}", outoken);
                                    },
                                    Err(e) => {
                                        error!("Failed to register outbound {:?} connection with event loop, {:?}", outoken, e);
                                        self.conns.remove(outoken);
                                    }
                                }
                            },
                            None => {
                                error!("Failed to insert outbound connection into slab");
                                //TODO: kill (close and unregister) inbound!
                            }
                        };
                    },
                    Err(e) => {
                        error!("Failed to register inbound {:?} connection with event loop, {:?}", token, e);
                        self.conns.remove(token);
                    }
                }
            },
            None => {
                // If we fail to insert, `conn` will go out of scope and be dropped.
                error!("Failed to insert inbound connection into slab");
            }
        };

        // We are using edge-triggered polling. Even our SERVER token needs to reregister.
        self.reregister(event_loop);
    }

    fn stop_flow(&mut self, token: Token) {
        let peer_token = self.find_connection_by_token(token).peer_token;
        debug!("Stopping flow {:?}+{:?}", token, peer_token);
        self.conns.remove(token);
        self.conns.remove(peer_token);
    }

    // update peer interest and re-register flows:
    fn flow_state(&mut self, state: BufState, token: Token, event_loop: &mut EventLoop<Nexus>) -> io::Result<()> {
        let peer_token = self.find_connection_by_token(token).peer_token;
       
        debug!("Re-registering flow {:?}+{:?} after read, inbound buf state: {:?}",
               token, peer_token, state);

        match self.find_connection_by_token(token).reregister(event_loop) {
            Ok(_) => {
                self.find_connection_by_token(peer_token).peer_read_interest(state);
                self.find_connection_by_token(peer_token).reregister(event_loop)
            },

            Err(e) => {
                warn!("Unable to re-register flow {:?} due to {:?}", token, e);
                Err(e)
            }
        }
    }

    fn flow_state2(&mut self, state: BufState, token: Token, event_loop: &mut EventLoop<Nexus>) -> io::Result<()> {
        let peer_token = self.find_connection_by_token(token).peer_token;
       
        debug!("Re-registering flow {:?}+{:?} after write, inbound buf state: {:?}",
               token, peer_token, state);

        match self.find_connection_by_token(token).reregister(event_loop) {
            Ok(_) => {
                self.find_connection_by_token(peer_token).peer_write_interest(state);
                self.find_connection_by_token(peer_token).reregister(event_loop)
            },

            Err(e) => {
                warn!("Unable to re-register flow {:?} due to {:?}", token, e);
                Err(e)
            }
        }
    }

    fn last(&mut self, token: Token) -> io::Result<BufState> {
        debug!("Handling write for token {:?}", token);
        let peer_token = self.conns[token].peer_token;
        let mut f1 = self.conns.remove(peer_token).unwrap();
        let result = self.conns[token].write_flow(token, &mut f1.buf);
        match self.conns.insert_with(|new_token| {
            debug!("Updated token {:?}", new_token);
            f1
        }) {
            Some(new_token) => {
                self.conns[token].peer_token = new_token;
                result
            },

            None => {
                warn!("Re-insert into the matrix failed for {:?}", token);
                Err(Error::new(ErrorKind::Other, "Matrix re-insertion failure"))
            }
        }

    }
    
    /// Find a connection in the slab using the given token.
    fn find_connection_by_token<'a>(&'a mut self, token: Token) -> &'a mut Flow {
        &mut self.conns[token]
    }
}

impl Handler for Nexus {
    type Timeout = ();
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Nexus>, token: Token, events: EventSet) {
        assert!(token != Token(0), "[BUG]: Received event for Token(0)");

        debug!("READY {:?} {:?}", token, events);

        if events.is_error() || events.is_hup() {
            warn!("Final event {:?} for token {:?}", events, token);
            self.stop_flow(token);
            return;
        }

        // We never expect a write event for our `Server` token . A write event for any other token
        // should be handed off to that connection.
        if events.is_writable() {
            debug!("Write event for {:?}", token);
            assert!(self.token != token, "Received writable event for Server");

            self.last(token)
            //self.find_connection_by_token(token).write_flow(token, &mut buf)
                .and_then(|buf_state| self.flow_state2(buf_state, token, event_loop))
                .unwrap_or_else(|e| {
                    warn!("write_dlow error {:?}, {:?}", e, token);
                    self.stop_flow(token);
                });
        }
        
        // A read event for our `Server` token means we are establishing a new connection. A read
        // event for any other token should be handed off to that connection.
        if events.is_readable() {
            if ACCEPTOR == token {
                self.accept(event_loop);
            } else {
                debug!("Read event for {:?}", token);
                self.find_connection_by_token(token).read_flow(token)
                    .and_then(|buf_state| self.flow_state(buf_state, token, event_loop))
                    .unwrap_or_else(|e| {
                        warn!("read_flow error {:?} for token {:?}", e, token);
                        self.stop_flow(token);
                    });
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
