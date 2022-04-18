use rand::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable};

use crate::circuit::Circuit;
use crate::garbling::{evaluate, garble, GarbledCircuit, InputKeysView, WireKey};
use crate::ot::{self, OTError};

/// An error that can happen while running our MPC protocol.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MPCError {
    /// We've already finished the protocol when trying to advance.
    AlreadyFinished,
    /// We received an unexpected message
    UnexpectedMessage,
    /// We failed to parse the result of an oblivious transfer as a WireKey
    InvalidWireKey,
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

impl Message {
    fn ot_messages(self) -> Result<Vec<ot::Message>, MPCError> {
        match self {
            Self::OTMessages(m) => Ok(m),
            _ => Err(MPCError::UnexpectedMessage),
        }
    }

    fn evaluation_request(self) -> Result<(), MPCError> {
        match self {
            Self::EvaluationRequest => Ok(()),
            _ => Err(MPCError::UnexpectedMessage),
        }
    }

    fn evaluation_response(self) -> Result<(Vec<WireKey>, GarbledCircuit), MPCError> {
        match self {
            Self::EvaluationResponse(keys, garbled) => Ok((keys, garbled)),
            _ => Err(MPCError::UnexpectedMessage),
        }
    }

    fn evaluation_result(self) -> Result<bool, MPCError> {
        match self {
            Self::EvaluationResult(b) => Ok(b),
            _ => Err(MPCError::UnexpectedMessage),
        }
    }
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
            Self::WaitForEvaluationStart { a_keys, garbled } => {
                message.evaluation_request()?;
                (
                    Self::EvaluationWait,
                    MPCOutput::Message(Message::EvaluationResponse(a_keys, garbled)),
                )
            }
            Self::EvaluationWait => {
                let result = message.evaluation_result()?;
                (Self::Done, MPCOutput::GarblerDone(result))
            }
            Self::Done => return Err(MPCError::AlreadyFinished),
        };
        *self = new_self;
        Ok(res)
    }
}

/// The evaluator is the second of the two parties in the MPC protocol.
///
/// They're responsible for evaluating the circuit with the input keys.
#[derive(Clone, Debug)]
enum Evaluator<'c> {
    ObliviousTransfer {
        circuit: &'c Circuit,
        receivers: Vec<ot::Receiver>,
    },
    RequestingEvaluation {
        b_keys: Vec<WireKey>,
        circuit: &'c Circuit,
    },
    Done,
}

impl<'c> Evaluator<'c> {
    pub fn create(inputs: &[Choice], circuit: &'c Circuit) -> Self {
        let receivers = inputs
            .iter()
            .map(|choice| ot::Receiver::new(*choice))
            .collect();
        Self::ObliviousTransfer { circuit, receivers }
    }

    pub fn advance<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        message: Message,
    ) -> Result<MPCOutput, MPCError> {
        let (new_self, res) = match std::mem::replace(self, Self::Done) {
            Self::ObliviousTransfer {
                circuit,
                mut receivers,
            } => {
                let ot_messages = message.ot_messages()?;

                let expected_len = receivers.len();
                let actual_len = ot_messages.len();
                if actual_len != expected_len {
                    return Err(MPCError::IncorrectOTMessageCount(actual_len, expected_len));
                }

                // Our receivers will all either produce WireKeys, or produce
                // further messages for the OT protocol. We collect both here.
                let mut b_keys = Vec::with_capacity(actual_len);
                let mut next_messages = Vec::with_capacity(actual_len);
                for (receiver, message) in receivers.iter_mut().zip(ot_messages) {
                    match receiver.advance(rng, message)? {
                        ot::OTOutput::Message(m) => next_messages.push(m),
                        ot::OTOutput::ReceiverOutput(r) => {
                            let key =
                                WireKey::try_from(&r[..]).map_err(|_| MPCError::InvalidWireKey)?;
                            b_keys.push(key);
                        }
                        // Our receivers will never output this variant
                        ot::OTOutput::SenderDone(_) => unreachable!(),
                    }
                }
                // Our implementation of OT will always take the same number of steps,
                // so we can assume that the results are either empty or full
                if next_messages.len() == expected_len {
                    (
                        Self::ObliviousTransfer { circuit, receivers },
                        MPCOutput::Message(Message::OTMessages(next_messages)),
                    )
                } else {
                    assert_eq!(b_keys.len(), expected_len);
                    (
                        Self::RequestingEvaluation { b_keys, circuit },
                        MPCOutput::Message(Message::EvaluationRequest),
                    )
                }
            }
            Self::RequestingEvaluation { b_keys, circuit } => {
                let (a_keys, garbled) = message.evaluation_response()?;
                let inputs_keys_view = InputKeysView { a_keys, b_keys };
                let result = evaluate(&inputs_keys_view, &garbled, circuit);
                (
                    Self::Done,
                    MPCOutput::EvaluatorDone(Message::EvaluationResult(result), result),
                )
            }
            Self::Done => return Err(MPCError::AlreadyFinished),
        };
        *self = new_self;
        Ok(res)
    }
}

#[cfg(test)]
mod test {
    use rand::rngs::OsRng;

    use super::*;

    fn execute_protocol(
        a_inputs: &[bool],
        b_inputs: &[bool],
        circuit: &Circuit,
    ) -> Result<bool, MPCError> {
        fn bools_to_choices(inputs: &[bool]) -> Vec<Choice> {
            let mut out = Vec::with_capacity(inputs.len());
            for input in inputs {
                out.push(Choice::from(u8::from(*input)));
            }
            out
        }

        let a_choices = bools_to_choices(a_inputs);
        let b_choices = bools_to_choices(b_inputs);

        let rng = &mut OsRng;

        let mut garbler = Garbler::create(rng, &a_choices, circuit);
        let mut evaluator = Evaluator::create(&b_choices, circuit);

        let mut message = Message::Start;
        let mut is_garbler = true;
        loop {
            if is_garbler {
                message = match garbler.advance(rng, message)? {
                    MPCOutput::Message(m) => m,
                    MPCOutput::GarblerDone(result) => return Ok(result),
                    MPCOutput::EvaluatorDone(_, _) => unreachable!(),
                }
            } else {
                message = match evaluator.advance(rng, message)? {
                    MPCOutput::Message(m) => m,
                    MPCOutput::GarblerDone(_) => unreachable!(),
                    MPCOutput::EvaluatorDone(m, _) => m,
                }
            }
            is_garbler = !is_garbler;
        }
    }

    #[test]
    fn test_mpc_evaluation() {
        use crate::circuit::{Circuit::*, Input::*};

        let circuit = Gate(
            0b1000,
            Box::new(Gate(0b1001, Box::new(Input(A(0))), Box::new(Input(B(0))))),
            Box::new(Gate(0b1001, Box::new(Input(A(1))), Box::new(Input(B(1))))),
        );

        assert_eq!(
            execute_protocol(&[false, false], &[false, true], &circuit),
            Ok(false)
        );
        assert_eq!(
            execute_protocol(&[false, false], &[false, false], &circuit),
            Ok(true)
        );
    }
}
