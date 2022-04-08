use rand::{CryptoRng, RngCore};
use subtle::Choice;

use crate::circuit::Circuit;

/// Represents a key hiding the value of a wire, essentially.
#[derive(Clone, Debug)]
pub struct WireKey {
    /// A key for our cipher of choice.
    pub half_key: [u8; 32],
    /// Which of the two entries this key is intended to decrypt.
    pub pointer: Choice,
}

/// This holds all of the keys we use for each of the inputs.
///
/// The idea is that each input has two keys associated with it. This data
/// structure holds these keys. We can then use these keys to run the interactive
/// portion of the protocol, by transmitting the correct keys to the other party.
pub struct InputKeys;

/// This holds only one of each key in InputKeys.
///
/// The evaluator creates this view with the help of the garbler, using
/// oblivious transfer to receive the right keys.
pub struct InputKeysView;

/// Represents an encrypted WireKey.
#[derive(Clone, Copy, Debug)]
struct EncryptedKey {
    /// The nonce used to encrypt the ciphertext.
    nonce: [u8; 12],
    /// The ciphertext includes the half key, and the pointer bit as a full byte.
    ciphertext: [u8; 33],
}

/// Represents an encrypted table holding the next encrypted key.
#[derive(Clone, Copy, Debug)]
struct EncryptedKeyTable {
    entries: [EncryptedKey; 4],
}

/// Represents the encryption of a single bit.
#[derive(Clone, Copy, Debug)]
struct EncryptedBit {
    /// The nonce used to encrypt this byte.
    nonce: [u8; 12],
    /// The encryption of either 0, or 1.
    ciphertext: [u8; 1],
}

/// Represents a table with the encrypted output of the circuit.
#[derive(Clone, Copy, Debug)]
struct EncryptedOutput {
    /// One entry for each of the possible output bits.
    entries: [EncryptedBit; 2],
}

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

/// Evaluate a garbled circuit using a view of the input keys, returning the output.
pub fn evaluate(view: InputKeysView, circuit: GarbledCircuit) -> bool {
    todo!()
}
