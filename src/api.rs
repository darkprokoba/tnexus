use std::sync::Arc;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::path::Path;
use std::net::SocketAddr;
use std::error::Error;
use std::fs::File;

use hyper::Server;
use hyper::server::Handler;
use hyper::server::Request;
use hyper::server::Response;
use hyper::server::Listening;
use hyper::status::StatusCode;
use hyper::net::HttpsListener;
use hyper::net::NetworkListener;
use hyper::net::Openssl;
use hyper::header::ContentType;
use hyper::mime::{Mime, TopLevel, SubLevel, Attr, Value};
use hyper::uri::RequestUri;

use openssl::ssl::{SslContext, SSL_OP_NO_TLSV1, SSL_OP_NO_TLSV1_1, SslMethod, SSL_VERIFY_PEER, SSL_VERIFY_FAIL_IF_NO_PEER_CERT};
use openssl::x509::X509;
use openssl::x509::X509FileType;
use openssl::x509::X509StoreContext;
use openssl::ssl::error::SslError;
use openssl::nid::Nid;

use std::collections::BTreeMap;

use mio::Sender as MioSender;

use rustc_serialize::json;

//const CIPHERS: &'static str = "DEFAULT";
const CIPHERS: &'static str = "AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA";

pub type SniMap = BTreeMap<String, String>;

pub enum ApiMsg {
    SniRequest(Sender<ApiMsg>),
    SniResponse(SniMap),
    Quit(Sender<ApiMsg>),
}

#[derive(RustcEncodable)]
pub struct ExampleResponse {
    map: SniMap,
}

#[derive(Clone, Debug)]
pub struct Api {
    key_path: String,
    cert_path: String,
    client_cert_path: String,
    main_channel: MioSender<ApiMsg>,
}

#[derive(Debug)]
pub struct RunningApi {
    api: Api,
    pub local_addr: SocketAddr,
    pub thread_handle: Listening,
}

impl Api {
    pub fn new(key: &str, cert: &str, client_cert: &str, main_channel: MioSender<ApiMsg>) -> Api {
        Api {
            key_path: key.to_string(),
            cert_path: cert.to_string(),
            client_cert_path: client_cert.to_string(),
            main_channel: main_channel,
        }
    }

    pub fn spawn(self) -> RunningApi {
        //let api = Api::new("api_key.pem", "api_cert.pem", "client_cert.pem");
        info!("Starting api endpoint: {:?}", self);
        //Openssl::with_cert_and_key
        let ssl = ctx(&self.cert_path, &self.key_path, path2pem(&self.client_cert_path))
        		.ok().expect("Could not initialize SSL context");
        let mut listener = HttpsListener::new("127.0.0.1:0", ssl)
                .expect("Could not initialize API listener");
        let local_addr = {
            let l2_ref = &mut listener;
            l2_ref.local_addr().expect("Could not determine API listener port")
        };
        let server = Server::new(listener);
        info!("API listeneing on {:?}", local_addr);
    
        let self_clone = self.clone();
        let listening = server.handle_threads(self_clone, 1).unwrap();
        
        RunningApi {
            api: self,
            local_addr: local_addr,
            thread_handle: listening,
        }
    }
}

fn respond(mut res: Response, code: StatusCode, body: &[u8]) {
    *res.status_mut() = code;
    res.send(body).ok().expect("Could not send response!");
}

impl Handler for Api {
    fn handle(&self, req: Request, mut res: Response) {
        match req.uri {
            RequestUri::AbsolutePath(path) => {
                info!("{}", path);
                let (tx, rx) = channel();
                if path == "/" {
                    let send_result = self.main_channel.send(ApiMsg::SniRequest(tx));
                    if send_result.is_err() {
                        println!("Error talking to main event_loop");
                        respond(res, StatusCode::InternalServerError, b"Error talking to main event_loop");
                    } else {
                        let response: ApiMsg = rx.recv().unwrap();
                        let sni_map = match response {
                            ApiMsg::SniResponse(rex) => rex,
                            _ => BTreeMap::new(),
                        };
            
            			let object = ExampleResponse {
            			    map: sni_map,
            			};
                        
                        let encoded = json::encode(&object).unwrap();
                        
                        res.headers_mut().set(ContentType(Mime(
                                TopLevel::Application, 
                                SubLevel::Json, 
                                vec![(Attr::Charset, Value::Utf8)])));
            
                        respond(res, StatusCode::Ok, encoded.as_bytes());
                    }
                } else if path == "/quit" {
                    let send_result = self.main_channel.send(ApiMsg::Quit(tx));
                    if send_result.is_err() {
                        println!("Error sending Quit to main event_loop");
                        respond(res, StatusCode::InternalServerError, b"Error sending Quit to main event_loop");
                    } else {
                        debug!("API shutdown not implemented!");
                        respond(res, StatusCode::Ok, b"User-initiated exit.");
                    }
                } else if path == "/about" {
                    respond(res, StatusCode::Ok, b"TODO: Implement me!"); 
                } else {
                    respond(res, StatusCode::NotFound, format!("Resource not found on server: {}", path).as_bytes());
                }
            },
            _ => {
                respond(res, StatusCode::BadRequest, b"Bad request");
            }
        }
    }
}

fn ctx<C, K>(cert: C, key: K, client_cert: Vec<u8>) -> Result<Openssl, SslError> 
        where C: AsRef<Path>, K: AsRef<Path> {
    
    let mut ctx = try!(SslContext::new(SslMethod::Sslv23));
    let opts = ctx.get_options();
    ctx.set_options(opts | SSL_OP_NO_TLSV1 | SSL_OP_NO_TLSV1_1);
    try!(ctx.set_cipher_list(CIPHERS));
    try!(ctx.set_certificate_file(cert.as_ref(), X509FileType::PEM));
    try!(ctx.set_private_key_file(key.as_ref(), X509FileType::PEM));
    ctx.set_verify_with_data(
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 
        verifier, 
        client_cert);
    Ok(Openssl { context: Arc::new(ctx) })
}

fn verifier(_preverify_ok: bool, x509_ctx: &X509StoreContext, client_cert: &Vec<u8>) -> bool {
    match x509_ctx.get_current_cert() {
    	None => {
    	    warn!("Rejecting client cert because X509StoreContext::get_current_cert() failed!");
    	    false
    	},
    	Some(cert) => {
    	    debug!("Client cert subject: {:?}", cert.subject_name().text_by_nid(Nid::CN));
    	    let mut buf = Vec::new();
    	    if cert.write_pem(&mut buf).is_err() {
    	        warn!("Rejecting client because peer cert could not be obtained");
    	        false
    	    } else {
    	        if buf == *client_cert {
    	            true
    	        } else {
                    warn!("Rejecting client cert {:?}", String::from_utf8(buf.clone()));
                    false
    	        }
    	    }
    	}
    }
}

fn path2pem(path1: &str) -> Vec<u8> {
    let path = Path::new(path1);

    let mut file = match File::open(&path) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => {
            let display = path.display();
            panic!("couldn't open {}: {}", display, Error::description(&why))
        },
        Ok(file) => file,
    };

    let cert = X509::from_pem(&mut file).expect("Unable to parse PEM"); //format!("Failed to parse pem {:?}", path1)
	let mut buf = Vec::new();
    cert.write_pem(&mut buf).expect("Unable to serialize PEM");

    buf
}
