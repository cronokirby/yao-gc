//! A module for oblivious transfer.
//!
//! Oblivious transfer is the fundamental protocol to building our MPC protocol.
//!
//! This implements the "Simplest OT" protocol, as seen in: https://eprint.iacr.org/2015/267.pdf

use blake3;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha8;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use subtle::Choice;

const DERIVE_KEY_FROM_POINT_CONTEXT: &'static str = "Yao-GC Derive Key From Point 2022-04-03";

fn kdf(point: &RistrettoPoint) -> [u8; 32] {
    blake3::derive_key(DERIVE_KEY_FROM_POINT_CONTEXT, point.compress().as_bytes())
}

/// Encrypt some data with a one time key.
///
/// The key shouldn't be used more than once.
fn encrypt_once(key: &[u8; 32], data: &mut [u8]) {
    let nonce = [0; 12];
    let mut cipher = ChaCha8::new(key.into(), &nonce.into());
    cipher.apply_keystream(data);
}

/// Represents an Error that can happen in the OT protocol.
#[derive(Clone, Copy, Debug, PartialEq)]
enum OTError {
    SenderAlreadyFinished,
    UnexpectedMessageType(Option<u8>),
}

#[derive(Clone, Debug)]
struct Message0 {
    point: RistrettoPoint,
}

#[derive(Clone, Debug)]
struct Message1 {
    point: RistrettoPoint,
}

#[derive(Clone, Debug)]
struct Message2 {
    c0: Vec<u8>,
    c1: Vec<u8>,
}

/// Represents a message that can be sent during the oblivious transfer protocol.
#[derive(Clone, Debug)]
enum Message {
    Start,
    /// The first message, sent from the sender to the receiver.
    M0(Message0),
    /// The second message, from the receiver to the sender.
    M1(Message1),
    /// The last message, from the sender to the receiver.
    ///
    /// The sender provides both messages, encrypted.
    M2(Message2),
}

impl Message {
    fn start(self) -> Result<(), OTError> {
        match self {
            Message::Start => Ok(()),
            Message::M0(_) => Err(OTError::UnexpectedMessageType(Some(0))),
            Message::M1(_) => Err(OTError::UnexpectedMessageType(Some(1))),
            Message::M2(_) => Err(OTError::UnexpectedMessageType(Some(2))),
        }
    }
    fn message0(self) -> Result<Message0, OTError> {
        match self {
            Message::Start => Err(OTError::UnexpectedMessageType(None)),
            Message::M0(m) => Ok(m),
            Message::M1(_) => Err(OTError::UnexpectedMessageType(Some(1))),
            Message::M2(_) => Err(OTError::UnexpectedMessageType(Some(2))),
        }
    }

    fn message1(self) -> Result<Message1, OTError> {
        match self {
            Message::Start => Err(OTError::UnexpectedMessageType(None)),
            Message::M0(_) => Err(OTError::UnexpectedMessageType(Some(0))),
            Message::M1(m) => Ok(m),
            Message::M2(_) => Err(OTError::UnexpectedMessageType(Some(2))),
        }
    }

    fn message2(self) -> Result<Message2, OTError> {
        match self {
            Message::Start => Err(OTError::UnexpectedMessageType(None)),
            Message::M0(_) => Err(OTError::UnexpectedMessageType(Some(0))),
            Message::M1(_) => Err(OTError::UnexpectedMessageType(Some(1))),
            Message::M2(m) => Ok(m),
        }
    }
}

/// Represents a partial output of advancing the oblivious transfer protocol.
///
/// This output is either the final result of the protocol, or a new message to send.
#[derive(Clone, Debug)]
enum OTOutput {
    Message(Message),
    SenderDone(Message),
    ReceiverOutput(Vec<u8>),
}

/// Represents the state of the sender.
///
/// The sender's goal is to transmit one of two messages, without learning which.
#[derive(Clone, Debug)]
enum Sender {
    S0 {
        /// The first message the receiver might have.
        m0: Vec<u8>,
        m1: Vec<u8>,
    },
    S1 {
        /// The first message the receiver might have.
        m0: Vec<u8>,
        /// The second message the receiver might have.
        m1: Vec<u8>,
        /// Our secret scalar.
        a: Scalar,
        /// Our secret scalar times the generator.
        big_a: RistrettoPoint,
    },
    S2,
}

impl Sender {
    fn advance<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: Message,
    ) -> Result<OTOutput, OTError> {
        let (new_self, res) = match std::mem::replace(self, Sender::S2) {
            Sender::S0 { m0, m1 } => {
                let a = Scalar::random(rng);
                let big_a = &a * &constants::RISTRETTO_BASEPOINT_TABLE;
                (
                    Sender::S1 { m0, m1, a, big_a },
                    OTOutput::Message(Message::M0(Message0 { point: big_a })),
                )
            }
            Sender::S1 {
                mut m0,
                mut m1,
                a,
                big_a,
            } => {
                let message1 = message.message1()?;
                let point0 = a * message1.point;
                let point1 = a * (message1.point - big_a);
                let key0 = kdf(&point0);
                let key1 = kdf(&point1);
                encrypt_once(&key0, &mut m0);
                encrypt_once(&key1, &mut m1);
                (
                    Sender::S2,
                    OTOutput::SenderDone(Message::M2(Message2 { c0: m0, c1: m1 })),
                )
            }
            Sender::S2 => return Err(OTError::SenderAlreadyFinished),
        };
        *self = new_self;
        Ok(res)
    }
}

/// Represents the state of the receiver.
///
/// The receiver's goal is to receive one of two messages, without learning
/// the other message, and without revealing which to sender.
#[derive(Clone, Debug)]
enum Receiver {
    R0 {
        /// Our secret choice of message.
        choice: Choice,
    },
    R1 {
        /// Our secret choice of message.
        choice: Choice,
        /// The secret key used to decrypt the message we'll get from the sender.
        key: [u8; 32],
    },
    R2,
}
