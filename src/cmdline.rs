use std::env::args;

#[derive(Debug)]
pub struct Args {
    pub listen: String,
    pub destination: String,
}

pub fn get_args() -> Args {
    let args: Vec<String> = args().collect();

    if args.len() < 3 {
        panic!("Usage: {} listen_ip:port destination_ip:port", args[0]);
    }

    Args {
        listen: args[1].clone(),
        destination: args[2].clone(),
    }
}
