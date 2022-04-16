use crate::garbling::GarbledCircuit;
use crate::ot;


/// An error that can happen while running our MPC protocol.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MPCError {
    /// We've already finished the protocol when trying to advance.
    AlreadyFinished,
    /// An error occurring from the underlying oblivious transfer.
    OTError(ot::OTError)
}

/// Represents some kind of message that can be sent during the MPC protocol.
#[derive(Clone, Debug)]
pub enum Message {
    /// We're sending messages associated with all of our OT instances.
    OTMessages(Vec<ot::Message>),
    /// The garbler sends over the circuit to evaluate.
    EvaluationRequest(GarbledCircuit),
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
struct Garbler {}

/// The evaluator is the second of the two parties in the MPC protocol.
/// 
/// They're responsible for evaluating the circuit with the input keys.
#[derive(Clone, Debug)]
struct Evaluator {}
