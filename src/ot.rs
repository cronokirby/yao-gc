//! A module for oblivious transfer.
//!
//! Oblivious transfer is the fundamental protocol to building our MPC protocol.
//!
//! This implements the "Simplest OT" protocol, as seen in: https://eprint.iacr.org/2015/267.pdf

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha8;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable};
use serde::{Serialize, Deserialize};

const DERIVE_KEY_FROM_POINT_CONTEXT: &'static str = "Yao-GC Derive Key From Point 2022-04-03";

/// Derive a key from a point.
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

/// Decrypt some data with a one time key.
fn decrypt(key: &[u8; 32], data: &mut [u8]) {
    // Yay, stream ciphers
    encrypt_once(key, data);
}

/// Represents an Error that can happen in the OT protocol.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OTError {
    AlreadyFinished,
    UnequalCiphertextLengths(usize, usize),
    UnexpectedMessageType(Option<u8>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Message0 {
    point: RistrettoPoint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Message1 {
    point: RistrettoPoint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Message2 {
    c0: Vec<u8>,
    c1: Vec<u8>,
}

/// Represents a message that can be sent during the oblivious transfer protocol.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Message {
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
pub enum OTOutput {
    /// We need to send a message to the other party.
    Message(Message),
    /// The sender has finished, and needs to send a final message to the receiver.
    SenderDone(Message),
    /// The receiver has finished, with some output value.
    ReceiverOutput(Vec<u8>),
}

/// Represents the state of the sender.
///
/// The sender's goal is to transmit one of two messages, without learning which.
#[derive(Clone, Debug)]
pub enum Sender {
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
    /// Create a new sender, with the two messages that need to be sent.
    pub fn new(m0: Vec<u8>, m1: Vec<u8>) -> Self {
        Self::S0 { m0, m1 }
    }

    /// Advance the sender, given a source of randomness, and the next message.
    ///
    /// The outcome is either an error, a message, or the output of the protocol.
    ///
    /// In the case of the sender, there's no output.
    pub fn advance<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: Message,
    ) -> Result<OTOutput, OTError> {
        let (new_self, res) = match std::mem::replace(self, Self::S2) {
            Self::S0 { m0, m1 } => {
                let a = Scalar::random(rng);
                let big_a = &a * &constants::RISTRETTO_BASEPOINT_TABLE;
                (
                    Self::S1 { m0, m1, a, big_a },
                    OTOutput::Message(Message::M0(Message0 { point: big_a })),
                )
            }
            Self::S1 {
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
                    Self::S2,
                    OTOutput::SenderDone(Message::M2(Message2 { c0: m0, c1: m1 })),
                )
            }
            Self::S2 => return Err(OTError::AlreadyFinished),
        };
        *self = new_self;
        Ok(res)
    }
}

fn conditional_assign_vec(out: &mut [u8], src: &[u8], choice: Choice) {
    for (x, y) in out.iter_mut().zip(src.iter()) {
        x.conditional_assign(y, choice);
    }
}

/// Represents the state of the receiver.
///
/// The receiver's goal is to receive one of two messages, without learning
/// the other message, and without revealing which to sender.
#[derive(Clone, Debug)]
pub enum Receiver {
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

impl Receiver {
    /// Create a new receiver, using their secret choice.
    pub fn new(choice: Choice) -> Receiver {
        Self::R0 { choice }
    }

    /// Advance the receiver, given a source of randomness, and the next message.
    ///
    /// The outcome is either an error, a message, or the output of the protocol.
    pub fn advance<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: Message,
    ) -> Result<OTOutput, OTError> {
        let (new_self, res) = match std::mem::replace(self, Receiver::R2) {
            Self::R0 { choice } => {
                let message0 = message.message0()?;

                let b = Scalar::random(rng);
                let key = kdf(&(b * message0.point));

                let mut big_b = &b * &constants::RISTRETTO_BASEPOINT_TABLE;
                let big_b_plus_a = big_b + message0.point;
                big_b.conditional_assign(&big_b_plus_a, choice);

                (
                    Self::R1 { choice, key },
                    OTOutput::Message(Message::M1(Message1 { point: big_b })),
                )
            }
            Self::R1 { choice, key } => {
                let Message2 { c0, c1 } = message.message2()?;
                // The sender is required to provide equal length ciphertexts, to avoid timing leaks.
                if c0.len() != c1.len() {
                    return Err(OTError::UnequalCiphertextLengths(c0.len(), c1.len()));
                }

                let mut c = c0;
                conditional_assign_vec(&mut c, &c1, choice);

                decrypt(&key, &mut c);

                (Self::R2, OTOutput::ReceiverOutput(c))
            }
            Self::R2 => return Err(OTError::AlreadyFinished),
        };
        *self = new_self;
        Ok(res)
    }
}

#[cfg(test)]
mod test {
    use rand::rngs::OsRng;

    use super::*;

    fn execute_protocol(m0: Vec<u8>, m1: Vec<u8>, choice: Choice) -> Result<Vec<u8>, OTError> {
        let rng = &mut OsRng;

        let mut s = Sender::new(m0, m1);
        let mut r = Receiver::new(choice);

        let mut message = Message::Start;
        let mut sender = true;
        loop {
            let was_sender = sender;
            sender = !sender;
            if was_sender {
                message = match s.advance(rng, message)? {
                    OTOutput::Message(m) => m,
                    OTOutput::SenderDone(m) => m,
                    OTOutput::ReceiverOutput(_) => unreachable!(),
                }
            } else {
                message = match r.advance(rng, message)? {
                    OTOutput::Message(m) => m,
                    OTOutput::SenderDone(_) => unreachable!(),
                    OTOutput::ReceiverOutput(output) => return Ok(output),
                }
            }
        }
    }

    #[test]
    fn executing_with_zero_works() {
        let m0 = b"hello".to_vec();
        let m1 = b"world".to_vec();
        let choice = Choice::from(0);
        assert_eq!(execute_protocol(m0.clone(), m1, choice), Ok(m0));
    }

    #[test]
    fn executing_with_one_works() {
        let m0 = b"hello".to_vec();
        let m1 = b"world".to_vec();
        let choice = Choice::from(1);
        assert_eq!(execute_protocol(m0, m1.clone(), choice), Ok(m1));
    }
}
