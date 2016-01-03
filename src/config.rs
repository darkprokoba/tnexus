use std::env::args;
use std::fs::File;
use std::io::Read;

use toml::{Parser, Value, Table};

const BUF_SIZE: usize = 1048576;

#[derive(Debug)]
pub struct Endpoint {
    pub bufsize: usize,
    pub listen: String,
    pub destination: String,
}

pub fn get_args() -> Endpoint {
    
    let mut input = String::new();
    File::open(&"tnexus.toml").and_then(|mut f| {
            f.read_to_string(&mut input)
        }).unwrap();
    let s: &str = &input[..]; 

    match Parser::new(s).parse() {
        None => {
            let args: Vec<String> = args().collect();
        
            if args.len() < 3 {
                panic!("Usage: {} listen_ip:port destination_ip:port", args[0]);
            }
        
            Endpoint {
                bufsize: BUF_SIZE,
                listen: args[1].clone(),
                destination: args[2].clone(),
            }
        },
    	Some(value) => parse_toml(&value),
    }

}

fn parse_toml(value: &Table) -> Endpoint {
    debug!("{:?}", value);

	let bufsize = match value.get("global") {
	    Some(&Value::Table(ref t)) => match t.get("bufsize") {
            Some(&Value::Integer(ref i)) => Some((*i) as usize),
            _ => None,
        },
        _ => None,
	}.unwrap_or(BUF_SIZE);
	
	match value.get("listen") {
	    Some(&Value::Array(ref a)) => parse_listen(bufsize, a),
	    _ => panic!("[[listen]] sections not found in config file!")
	}
}

fn parse_listen(bufsize: usize, listens: &Vec<Value>) -> Endpoint {
    if listens.is_empty() {
        panic!("Invalid configuration file: empty [[listen]] section!");
    }
    
	//TODO: currently only one listening endpoint is supported
	//this limitation will be lifted in the future.
    match listens[0] {
		Value::Table(ref t) => {
		    let name = get_str_attr("name", t);
		    let endpoint = get_str_attr("endpoint", t);
		    let destination = get_str_attr("destination", t);

		    debug!("endpoint {} {} {}", name, endpoint, destination);
		    Endpoint {
                bufsize: bufsize,
                listen: endpoint,
                destination: destination
		    }
		},
		_ => panic!("Invalid configration file: listen section should be an array of tables"),        
    }
}

fn get_str_attr(attr: &str, table: &Table) -> String {
    match table.get(attr) {
        Some(&Value::String(ref result)) => result.clone(),
        _ => panic!("Invalid configration file: No String({}) attribute in {:?}", attr, table),
    }
}
