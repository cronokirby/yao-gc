use rand::{CryptoRng, RngCore};
use subtle::Choice;

use crate::circuit::Circuit;

/// Represents a key hiding the value of a wire, essentially.
#[derive(Clone, Debug)]
pub struct InputKey {
    /// A key half the size of an encryption key.
    ///
    /// When combined with another key, we can do some encryption.
    pub half_key: [u8; 16],
    /// Which of the two entries this key is intended to decrypt.
    pub pointer: Choice,
}

/// This holds all of the keys we use for each of the inputs.
///
/// The idea is that each input has two keys associated with it. This data
/// structure holds these keys. We can then use these keys to run the interactive
/// portion of the protocol, by transmitting the correct keys to the other party.
pub struct InputKeys;

/// Represents a Garbled Circuit.
///
/// This can be seen as an encrypted version of the circuit we want to evaluate.
/// Given the correct keys for each input to the circuit, we can evaluate the
/// final result.
pub struct GarbledCircuit;

/// Garble a circuit, given a source of randomness.
///
/// The input keys contain enough information to decrypt the circuit completely,
/// which is why we need the only transmit some of these keys during the rest
/// of the protocol.
pub fn garble<R: RngCore + CryptoRng>(
    rng: &mut R,
    circuit: Circuit,
) -> (InputKeys, GarbledCircuit) {
    todo!()
}