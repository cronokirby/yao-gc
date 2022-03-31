/// Represents an initial input to the circuit.
///
/// The inputs to the circuit either come from player A, or from player B.
///
/// We use a u32 as an index, representing the ith input of that player to the circuit.
#[derive(Clone, Copy, Debug)]
pub enum Input {
    /// An indexed input from player A.
    A(u32),
    /// An indexed input from player B.
    B(u32),
}

/// Represents a gate taking in a single input.
///
/// Strictly speaking, this can only be the not gate, or a useless identity gate.
/// Omitting the identity gate makes sense, because that would add needless complexity.
#[derive(Clone, Copy, Debug)]
pub enum Gate1 {
    Not,
}

/// Represents a gate taking in two inputs, expressible in our syntax.
///
/// Not all gates are included here, just the ones we have in the language.
#[derive(Clone, Copy, Debug)]
pub enum Gate2 {
    Or,
    And,
    Xor,
    Equal,
}

/// Represents a syntax tree obtained after parsing.
///
/// This directly represents the elements of our language, and is not necessarily
/// a fully optimized circuit representation.
#[derive(Clone, Debug)]
pub enum AST {
    /// An input to the circuit.
    Input(Input),
    /// A gate taking in one input.
    Gate1(Gate1, Box<AST>, Box<AST>),
    /// A gate taking in two inputs.
    Gate2(Gate2, Box<AST>, Box<AST>),
}
