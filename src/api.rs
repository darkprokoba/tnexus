use std::thread;
use std::sync::Arc;
use std::path::Path;
use std::net::SocketAddr;
use std::error::Error;
use std::fs::File;

use hyper::Server;
use hyper::server::Request;
use hyper::server::Response;
use hyper::net::HttpsListener;
use hyper::net::NetworkListener;
use hyper::net::Openssl;

use openssl::ssl::{SslContext, SSL_OP_NO_TLSV1, SSL_OP_NO_TLSV1_1, SslMethod, SSL_VERIFY_PEER, SSL_VERIFY_FAIL_IF_NO_PEER_CERT};
use openssl::x509::X509;
use openssl::x509::X509FileType;
use openssl::x509::X509StoreContext;
use openssl::ssl::error::SslError;
use openssl::nid::Nid;

//const CIPHERS: &'static str = "DEFAULT";
const CIPHERS: &'static str = "AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA";

#[derive(Debug)]
pub struct Api {
    key_path: String,
    cert_path: String,
    client_cert_path: String,
}

impl Api {
    pub fn new(key: &str, cert: &str, client_cert: &str) -> Api {
        Api {
            key_path: key.to_string(),
            cert_path: cert.to_string(),
            client_cert_path: client_cert.to_string(),
        }
    }

    pub fn spawn(&self) -> SocketAddr {
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
    
        thread::spawn(move || {
            server.handle_threads(hello, 1).unwrap();
        });
        
        local_addr
    }
}

fn hello(_: Request, res: Response) {
    res.send(b"Hello World!").unwrap();
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