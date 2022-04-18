mod circuit;
mod garbling;
mod mpc;
mod ot;
use rmp_serde::{decode, encode};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::{fs, io};

use rand::rngs::OsRng;
use structopt::StructOpt;
use subtle::{Choice, ConstantTimeEq};

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
    address: String,
}

/// Represents the kind of error that can happen in our application
#[derive(Debug)]
enum AppError {
    Input(usize, usize),
    Compile(circuit::CompileError),
    Encode(encode::Error),
    Decode(decode::Error),
    Mpc(mpc::MPCError),
    IO(io::Error),
}

impl From<circuit::CompileError> for AppError {
    fn from(e: circuit::CompileError) -> Self {
        Self::Compile(e)
    }
}

impl From<encode::Error> for AppError {
    fn from(e: encode::Error) -> Self {
        Self::Encode(e)
    }
}

impl From<decode::Error> for AppError {
    fn from(e: decode::Error) -> Self {
        Self::Decode(e)
    }
}

impl From<mpc::MPCError> for AppError {
    fn from(e: mpc::MPCError) -> Self {
        Self::Mpc(e)
    }
}

impl From<io::Error> for AppError {
    fn from(e: io::Error) -> Self {
        Self::IO(e)
    }
}

#[derive(Debug)]
struct MessagePipe {
    stream: TcpStream,
}

impl MessagePipe {
    /// Listen until we receive a connection.
    pub fn listen(address: &str) -> Result<Self, AppError> {
        let listener = TcpListener::bind(address)?;
        let (stream, _) = listener.accept()?;
        Ok(Self { stream })
    }

    /// Connect to the other end of the pipe.
    pub fn connect(address: &str) -> Result<Self, AppError> {
        let stream = TcpStream::connect(address)?;
        Ok(Self { stream })
    }

    /// Write a message along this pipe.
    pub fn write(&mut self, message: mpc::Message) -> Result<(), AppError> {
        encode::write(&mut self.stream, &message)?;
        Ok(())
    }

    /// Read a message from this pipe.
    pub fn read(&mut self) -> Result<mpc::Message, AppError> {
        let message = decode::from_read(&mut self.stream);
        Ok(message?)
    }
}

fn read_inputs(required: usize) -> Result<Vec<Choice>, AppError> {
    println!("input:");
    let mut line = String::with_capacity(required);
    io::stdin().read_line(&mut line)?;
    let content = line.trim();
    if content.len() != required {
        return Err(AppError::Input(content.len(), required));
    }
    let mut out = Vec::with_capacity(required);
    for c in content.bytes() {
        out.push(c.ct_eq(&b"1"[0]));
    }
    Ok(out)
}

fn listen(circuit: &circuit::Circuit, address: &str) -> Result<bool, AppError> {
    let (required, _) = circuit.input_counts();
    let inputs = read_inputs(required)?;

    let mut pipe = MessagePipe::listen(address)?;
    let mut garbler = mpc::Garbler::create(&mut OsRng, &inputs, circuit);

    loop {
        let message = pipe.read()?;
        match garbler.advance(&mut OsRng, message)? {
            mpc::MPCOutput::Message(msg) => pipe.write(msg)?,
            mpc::MPCOutput::GarblerDone(res) => return Ok(res),
            mpc::MPCOutput::EvaluatorDone(_, _) => unreachable!(),
        }
    }
}

fn connect(circuit: &circuit::Circuit, address: &str) -> Result<bool, AppError> {
    let (_, required) = circuit.input_counts();
    let inputs = read_inputs(required)?;

    let mut pipe = MessagePipe::connect(address)?;
    let mut evaluator = mpc::Evaluator::create(&inputs, circuit);

    pipe.write(mpc::Message::Start)?;

    loop {
        let message = pipe.read()?;
        match evaluator.advance(&mut OsRng, message)? {
            mpc::MPCOutput::Message(msg) => pipe.write(msg)?,
            mpc::MPCOutput::GarblerDone(_) => unreachable!(),
            mpc::MPCOutput::EvaluatorDone(msg, res) => {
                pipe.write(msg)?;
                return Ok(res);
            }
        }
    }
}

fn read_circuit(path: &Path) -> Result<circuit::Circuit, AppError> {
    let circuit_string = fs::read_to_string(path)?;
    let circuit = circuit::compile(&circuit_string)?;
    Ok(circuit)
}

fn main() -> Result<(), AppError> {
    let args = Args::from_args();

    let circuit = read_circuit(&args.circuit)?;

    let result = if args.listen {
        listen(&circuit, &args.address)?
    } else {
        connect(&circuit, &args.address)?
    };

    println!("{}", result);
    Ok(())
}
