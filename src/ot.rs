//! A module for oblivious transfer.
//!
//! Oblivious transfer is the fundamental protocol to building our MPC protocol.
//!
//! This implements the "Simplest OT" protocol, as seen in: https://eprint.iacr.org/2015/267.pdf

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use subtle::Choice;

/// Represents a message that can be sent during the oblivious transfer protocol.
enum Message {
    /// The first message, sent from the sender to the receiver.
    M0(RistrettoPoint),
    /// The second message, from the receiver to the sender.
    M1(RistrettoPoint),
    /// The last message, from the sender to the receiver.
    ///
    /// The sender provides both messages, encrypted.
    M2(Vec<u8>, Vec<u8>),
}

/// Represents the state of the sender.
///
/// The sender's goal is to transmit one of two messages, without learning which.
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
    },
    S2,
}

/// Represents the state of the receiver.
///
/// The receiver's goal is to receive one of two messages, without learning
/// the other message, and without revealing which to sender.
enum Receiver {
    S0 {
        /// Our secret choice of message.
        choice: Choice,
    },
    S1 {
        /// Our secret choice of message.
        choice: Choice,
        /// The secret key used to decrypt the message we'll get from the sender.
        key: [u8; 32],
    },
}
