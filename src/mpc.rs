use rand::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable};

use crate::circuit::Circuit;
use crate::garbling::{garble, GarbledCircuit, WireKey, WireKeyPair};
use crate::ot::{self, OTError};

/// An error that can happen while running our MPC protocol.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MPCError {
    /// We've already finished the protocol when trying to advance.
    AlreadyFinished,
    /// We received an unexpected message
    UnexpectedMessage,
    /// We've received the wrong number of OT messages.
    IncorrectOTMessageCount(usize, usize),
    /// An error occurring from the underlying oblivious transfer.
    OTError(ot::OTError),
}

impl From<ot::OTError> for MPCError {
    fn from(e: ot::OTError) -> Self {
        Self::OTError(e)
    }
}

/// Represents some kind of message that can be sent during the MPC protocol.
#[derive(Clone, Debug)]
pub enum Message {
    /// The first message to initiate the garbler.
    Start,
    /// We're sending messages associated with all of our OT instances.
    OTMessages(Vec<ot::Message>),
    /// The evaluator requests to evaluate the circuit
    EvaluationRequest,
    /// The garbler sends over the circuit to evaluate.
    EvaluationResponse(Vec<WireKey>, GarbledCircuit),
    /// The evaluator returns the result of the evaluation
    EvaluationResult(bool),
}

/// The output return when advancing the state of one of the parties.
#[derive(Clone, Debug)]
pub enum MPCOutput {
    /// The party would like to send a message.
    Message(Message),
    /// The garbler has finished with a result.
    GarblerDone(bool),
    /// The evaluate has finished with a result, but needs to send one last message.
    EvaluatorDone(Message, bool),
}

/// The Garbler is the first of the two parties in the MPC protocol.
///
/// The Garbler creates the garbled circuit and sends it to the evaluator.
#[derive(Clone, Debug)]
enum Garbler {
    ObliviousTransfer {
        a_keys: Vec<WireKey>,
        garbled: GarbledCircuit,
        senders: Vec<ot::Sender>,
    },
    WaitForEvaluationStart {
        a_keys: Vec<WireKey>,
        garbled: GarbledCircuit,
    },
    EvaluationWait,
    Done,
}

impl Garbler {
    /// Create a garbler from a circuit and its inputs.
    ///
    /// This needs access to randomness to actually garble the circuit.
    pub fn create<R: RngCore + CryptoRng>(
        rng: &mut R,
        inputs: &[Choice],
        circuit: &Circuit,
    ) -> Self {
        let (input_keys, garbled) = garble(rng, circuit);
        let senders = input_keys
            .b_keys
            .iter()
            .map(|(k0, k1)| ot::Sender::new(k0.into(), k1.into()))
            .collect();
        assert_eq!(inputs.len(), input_keys.a_keys.len());
        let a_keys = input_keys
            .a_keys
            .iter()
            .zip(inputs)
            .map(|((k0, k1), &choice)| WireKey::conditional_select(k0, k1, choice))
            .collect();
        Self::ObliviousTransfer {
            a_keys,
            garbled,
            senders,
        }
    }

    pub fn advance<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: Message,
    ) -> Result<MPCOutput, MPCError> {
        let (new_self, res) = match std::mem::replace(self, Self::Done) {
            Self::ObliviousTransfer {
                a_keys,
                garbled,
                mut senders,
            } => match message {
                Message::Start => {
                    let messages_result: Result<Vec<_>, OTError> = senders
                        .iter_mut()
                        .map(|sender| match sender.advance(rng, ot::Message::Start)? {
                            ot::OTOutput::Message(m) => Ok(m),
                            _ => panic!("OT sending start didn't produce a message"),
                        })
                        .collect();
                    let messages = messages_result?;
                    (
                        Self::ObliviousTransfer {
                            a_keys,
                            garbled,
                            senders,
                        },
                        MPCOutput::Message(Message::OTMessages(messages)),
                    )
                }
                Message::OTMessages(ot_messages) => {
                    // Because we're receiving this message, we have no guarantee
                    // that it has the right number of OT components.
                    let expected_len = senders.len();
                    let actual_len = ot_messages.len();
                    if actual_len != expected_len {
                        return Err(MPCError::IncorrectOTMessageCount(actual_len, expected_len));
                    }

                    let mut done_count = 0;
                    let mut next_messages = Vec::with_capacity(senders.len());

                    for (sender, message) in senders.iter_mut().zip(ot_messages) {
                        match sender.advance(rng, message)? {
                            ot::OTOutput::Message(m) => next_messages.push(m),
                            ot::OTOutput::SenderDone(m) => {
                                next_messages.push(m);
                                done_count += 1
                            }
                            // The sender will never output this variant
                            ot::OTOutput::ReceiverOutput(_) => unreachable!(),
                        }
                    }

                    if done_count == 0 {
                        (
                            Self::ObliviousTransfer {
                                a_keys,
                                garbled,
                                senders,
                            },
                            MPCOutput::Message(Message::OTMessages(next_messages)),
                        )
                    } else if done_count == senders.len() {
                        (
                            Self::WaitForEvaluationStart { a_keys, garbled },
                            MPCOutput::Message(Message::OTMessages(next_messages)),
                        )
                    } else {
                        // All of the OT senders will finish at the same time
                        unreachable!()
                    }
                }
                _ => return Err(MPCError::UnexpectedMessage),
            },
            _ => unimplemented!(),
        };
        *self = new_self;
        Ok(res)
    }
}

/// The evaluator is the second of the two parties in the MPC protocol.
///
/// They're responsible for evaluating the circuit with the input keys.
#[derive(Clone, Debug)]
struct Evaluator {}
