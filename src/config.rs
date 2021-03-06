use std::env::args;
use std::fs::File;
use std::io::Read;
use std::collections::BTreeMap;

use mio::Sender;

use toml::{Parser, Value, Table};

use api::Api;
use api::RunningApi;
use api::ApiMsg;
use multiplex::{Multiplexer, FixedPlexer, SniPlexer};

const BUF_SIZE: usize = 1048576;

#[derive(Debug)]
pub struct Endpoint {
    pub bufsize: usize,
    pub listen: String,
    pub destination: Box<Multiplexer>,
    pub api: Option<RunningApi>,
}

pub fn configure(main_channel: Sender<ApiMsg>) -> Endpoint {

    let mut input = String::new();
    File::open(&"tnexus.toml").and_then(|mut f| {
            f.read_to_string(&mut input)
        }).unwrap();

    match Parser::new(&input).parse() {
        None => {
            let args: Vec<String> = args().collect();
        
            if args.len() < 3 {
                panic!("Usage: {} listen_ip:port destination_ip:port", args[0]);
            }
        
            Endpoint {
                bufsize: BUF_SIZE,
                listen: args[1].clone(),
                destination: Box::new(FixedPlexer::new(&args[2])),
                api: None,
            }
        },
    	Some(value) => parse_toml(&value, main_channel),
    }

}

fn parse_toml(value: &Table, main_channel: Sender<ApiMsg>) -> Endpoint {
    debug!("{:?}", value);

	let bufsize = match value.get("global") {
	    Some(&Value::Table(ref t)) => match t.get("bufsize") {
            Some(&Value::Integer(ref i)) => Some((*i) as usize),
            _ => None,
        },
        _ => None,
	}.unwrap_or(BUF_SIZE);
	
	match value.get("listen") {
	    Some(&Value::Array(ref a)) => parse_listen(bufsize, a, main_channel),
	    _ => panic!("[[listen]] sections not found in config file!")
	}
}

fn parse_listen(bufsize: usize, listens: &Vec<Value>, main_channel: Sender<ApiMsg>) -> Endpoint {
    if listens.is_empty() {
        panic!("Invalid configuration file: empty [[listen]] section!");
    }
    
	//TODO: currently only one listening endpoint is supported
	//this limitation will be lifted in the future.
    match listens[0] {
		Value::Table(ref t) => {
		    let name = get_str_attr("name", t);
		    let endpoint = get_str_attr("endpoint", t);

		    match t.get("multiplex") {
		        Some(&Value::Table(ref mt)) => {
		            let default = get_str_attr("sni_missing", t);
		            let mut sni_map = get_sni_map(mt);

                    let api_key = get_str("api_key", t);
                    let running_api = if api_key.is_some() {
                        let api_cert = get_str_attr("api_cert", t);
                        let api_authorized_cert = get_str_attr("api_authorized_cert", t);
                        let api = Api::new(&api_key.unwrap(), &api_cert, &api_authorized_cert, main_channel);
            	        let running_api = api.spawn();
            	        sni_map.insert("tnexus.net".to_string(), format!("127.0.0.1:{}", running_api.local_addr.port()));
            	        Some(running_api)
                    } else {
                        None
                    };

        		    debug!("[{}] Forwarding {} to {:?}", name, endpoint, sni_map);

        		    Endpoint {
                        bufsize: bufsize,
                        listen: endpoint,
                        destination: Box::new(SniPlexer::new(&default, sni_map)),
                        api: running_api,
        		    }
		        },
		        _ => {
        		    let destination = get_str_attr("destination", t);
        		    debug!("[{}] Forwarding {} to {}", name, endpoint, destination);
        
        		    Endpoint {
                        bufsize: bufsize,
                        listen: endpoint,
                        destination: Box::new(FixedPlexer::new(&destination)),
                        api: None,
        		    }
		        }
		    }
		},
		_ => panic!("Invalid configration file: listen section should be an array of tables"),        
    }
}

fn get_str_attr(attr: &str, table: &Table) -> String {
    get_str(attr, table).expect(
        &format!("Invalid configration file: No String({}) attribute in {:?}", attr, table))
}

fn get_str(attr: &str, table: &Table) -> Option<String> {
    match table.get(attr) {
        Some(&Value::String(ref result)) => Some(result.clone()),
        _ => None,
    }
}

fn get_sni_map(multiplex: &BTreeMap<String, Value>) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    
    for (key, value) in multiplex.iter() {
        match value {
            &Value::String(ref val) => {
                result.insert(key.clone(), val.clone());
            },
            _ => panic!("Invalid configration file: Bad SNI map: {:?}", multiplex),
        }
    }
    
    result
}
