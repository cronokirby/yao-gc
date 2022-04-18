mod circuit;
mod garbling;
mod mpc;
mod ot;
use std::path::PathBuf;

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Args {
    /// If true, then this will be the garbler listening for connections
    #[structopt(short, long)]
    listen: bool,
    /// The path to the circuit file
    #[structopt(short, long, parse(from_os_str))]
    circuit: PathBuf,
    /// The network address to listen on, or to connect to
    #[structopt(name = "ADDRESS")]
    address: String
}

fn main() {
    let args = Args::from_args();
    println!("{:?}", args);
}
