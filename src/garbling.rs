use chacha20::{cipher::KeyIvInit, cipher::StreamCipher, XChaCha8};
use rand::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable};

use crate::circuit::Circuit;

/// Apply a compact gate representation to two bits
fn apply_gate(gate: u8, a: bool, b: bool) -> bool {
    // We interpret the first two bits as a two bit index, and use that
    // to access the corresponding output bit inside of the gate.
    ((gate >> ((u8::from(a) << 1) | u8::from(b))) & 1) == 1
}

/// Represents a key hiding the value of a wire, essentially.
#[derive(Clone, Copy, Debug)]
pub struct WireKey {
    /// A key for our cipher of choice.
    pub key: [u8; 32],
    /// Which of the two entries this key is intended to decrypt.
    pub pointer: Choice,
}

pub type WireKeyPair = (WireKey, WireKey);

impl WireKey {
    /// Generate a random pair of wire keys.
    ///
    /// Generating them in a pair is important, so that one pointer bit is
    /// the opposite of the other pointer bit.
    fn random_pair<R: RngCore + CryptoRng>(rng: &mut R) -> (WireKey, WireKey) {
        let mut key0 = [0u8; 32];
        rng.fill_bytes(&mut key0);
        let mut key1 = [0u8; 32];
        rng.fill_bytes(&mut key1);
        let pointer0 = Choice::from((rng.next_u32() & 1) as u8);
        let pointer1 = !pointer0;
        (
            WireKey {
                key: key0,
                pointer: pointer0,
            },
            WireKey {
                key: key1,
                pointer: pointer1,
            },
        )
    }

    fn encrypt<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        key_a: &WireKey,
        key_b: &WireKey,
    ) -> EncryptedKey {
        let mut key = key_a.key;
        for i in 0..32 {
            key[i] ^= key_b.key[i];
        }

        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);

        let mut ciphertext = [0u8; 33];
        ciphertext[..32].copy_from_slice(&self.key);
        ciphertext[33] = self.pointer.unwrap_u8();

        let mut cipher = XChaCha8::new(&key.into(), &nonce.into());
        cipher.apply_keystream(&mut ciphertext);

        EncryptedKey { nonce, ciphertext }
    }
}

/// This holds all of the keys we use for each of the inputs.
///
/// The idea is that each input has two keys associated with it. This data
/// structure holds these keys. We can then use these keys to run the interactive
/// portion of the protocol, by transmitting the correct keys to the other party.
#[derive(Clone, Debug)]
pub struct InputKeys {
    // For each participant's bit, we hold both of the keys they might use.
    a_keys: Vec<WireKeyPair>,
    b_keys: Vec<WireKeyPair>,
}

/// This holds only one of each key in InputKeys.
///
/// The evaluator creates this view with the help of the garbler, using
/// oblivious transfer to receive the right keys.
#[derive(Clone, Debug)]
pub struct InputKeysView {
    // For each participant's bit, we hold the key representing their choice bit.
    a_keys: Vec<WireKey>,
    b_keys: Vec<WireKey>,
}

/// Represents an encrypted WireKey.
#[derive(Clone, Copy, Debug)]
struct EncryptedKey {
    /// The nonce used to encrypt the ciphertext.
    nonce: [u8; 24],
    /// The ciphertext includes the half key, and the pointer bit as a full byte.
    ciphertext: [u8; 33],
}

impl ConditionallySelectable for EncryptedKey {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut nonce = [0; 24];
        for (i, nonce_i) in nonce.iter_mut().enumerate() {
            *nonce_i = u8::conditional_select(&a.nonce[i], &b.nonce[i], choice);
        }
        let mut ciphertext = [0; 33];
        for (i, ciphertext_i) in ciphertext.iter_mut().enumerate() {
            *ciphertext_i = u8::conditional_select(&a.ciphertext[i], &b.ciphertext[i], choice);
        }
        Self { nonce, ciphertext }
    }
}

/// Represents an encrypted table holding the next encrypted key.
#[derive(Clone, Copy, Debug)]
struct EncryptedKeyTable {
    table: [EncryptedKey; 4],
}

impl EncryptedKeyTable {
    fn build<R: CryptoRng + RngCore>(
        rng: &mut R,
        gate: u8,
        input_a: WireKeyPair,
        input_b: WireKeyPair,
        output: WireKeyPair,
    ) -> Self {
        let (out0, out1) = output;

        let out_wire = |a, b| {
            if apply_gate(gate, a, b) {
                out1
            } else {
                out0
            }
        };

        let mut out00 = out_wire(false, false).encrypt(rng, &input_a.0, &input_b.0);
        let mut out01 = out_wire(false, true).encrypt(rng, &input_a.0, &input_b.1);
        let mut out10 = out_wire(true, false).encrypt(rng, &input_a.1, &input_b.0);
        let mut out11 = out_wire(true, true).encrypt(rng, &input_a.1, &input_b.1);

        EncryptedKey::conditional_swap(&mut out00, &mut out10, input_a.0.pointer);
        EncryptedKey::conditional_swap(&mut out01, &mut out11, input_a.0.pointer);
        EncryptedKey::conditional_swap(&mut out00, &mut out01, input_b.0.pointer);
        EncryptedKey::conditional_swap(&mut out10, &mut out11, input_b.0.pointer);

        Self {
            table: [out00, out01, out10, out11],
        }
    }
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
