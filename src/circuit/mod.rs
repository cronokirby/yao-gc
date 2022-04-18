mod ast;
mod lexer;

use std::{error::Error, fmt};

pub use ast::Input;

use ast::{parse, ParseError};
use lexer::{lex, LexError};

/// Represents a boolean circuit, over the respective inputs of both parties.
#[derive(Clone, Debug)]
pub enum Circuit {
    /// Represents one of the inputs of the parties.
    Input(Input),
    /// Represents the negation of one of the inputs of the parties.
    NegatedInput(Input),
    /// Represents an arbitrary gate taking in two wires.
    ///
    /// A boolean function on two inputs as 16 possible outputs, so 4 bits are
    /// sufficient to specify it, one for each of the possible input pairs.
    /// We use the low 4 bits of a u8 to specify that.
    Gate(u8, Box<Circuit>, Box<Circuit>),
}

impl Circuit {
    /// Modify this circuit to have its output negated.
    fn negate(&mut self) {
        use Circuit::*;

        match self {
            Input(i) => *self = NegatedInput(*i),
            NegatedInput(i) => *self = Input(*i),
            Gate(g, _, _) => *g = invert_gate_output(*g),
        }
    }

    /// Return the maximum input values used in the circuit, for each side, plus 1.
    ///
    /// If an input side happened to not be used, 0 would be used for that side.
    pub fn input_counts(&self) -> (usize, usize) {
        fn input_counts_on_input(input: Input) -> (usize, usize) {
            match input {
                Input::A(x) => (x as usize + 1, 0),
                Input::B(x) => (0, x as usize + 1),
            }
        }

        match self {
            Circuit::Input(i) | Circuit::NegatedInput(i) => input_counts_on_input(*i),
            Circuit::Gate(_, left, right) => {
                let (a0, b0) = left.input_counts();
                let (a1, b1) = right.input_counts();
                (a0.max(a1), b0.max(b1))
            }
        }
    }
}

/// Convert a syntactical gate into a lookup table gate.
fn gate2_to_u8(gate: ast::Gate2) -> u8 {
    use ast::Gate2::*;

    match gate {
        And => 0b1000,
        Or => 0b1110,
        Xor => 0b0110,
        Equal => 0b1001,
    }
}

/// Return an equivalent gate, with all the output bits flipped.
fn invert_gate_output(g: u8) -> u8 {
    // To invert the output, simply flip each bit in the lookup table
    0b1111 ^ g
}

/// Convert a raw syntactical AST into an optimized circuit.
fn optimize(ast: ast::AST) -> Circuit {
    use ast::Gate1::*;
    use ast::AST::*;

    match ast {
        Input(i) => Circuit::Input(i),
        // We know it's a not gate
        Gate1(Not, a) => {
            let mut circuit = optimize(*a);
            circuit.negate();
            circuit
        }
        Gate2(g, a1, a2) => {
            let c1 = optimize(*a1);
            let c2 = optimize(*a2);
            let gate = gate2_to_u8(g);
            Circuit::Gate(gate, Box::new(c1), Box::new(c2))
        }
    }
}

// We have a separate enum in order to avoid exposing the enum variants publicly.
#[derive(Debug, PartialEq)]
enum CompileErrorInner {
    LexError(lexer::LexError),
    ParseError(ast::ParseError),
}

/// Represents an error that can happen when compiling a source program into a circuit.
///
/// Errors happen when lexing the source program into tokens, or when parsing those
/// tokens into a representation of the circuit.
#[derive(Debug, PartialEq)]
pub struct CompileError(CompileErrorInner);

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CompileErrorInner::*;

        match &self.0 {
            LexError(e) => write!(f, "lexer error: {}", e),
            ParseError(e) => write!(f, "parser error: {}", e),
        }
    }
}

impl Error for CompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use CompileErrorInner::*;

        match &self.0 {
            LexError(e) => e.source(),
            ParseError(e) => e.source(),
        }
    }
}

impl From<LexError> for CompileError {
    fn from(e: LexError) -> Self {
        CompileError(CompileErrorInner::LexError(e))
    }
}

impl From<ParseError> for CompileError {
    fn from(e: ParseError) -> Self {
        CompileError(CompileErrorInner::ParseError(e))
    }
}

/// Compile a source program into a circuit.
///
/// This might fail if the source program is incorrectly formed.
pub fn compile(src: &str) -> Result<Circuit, CompileError> {
    let tokens = lex(src)?;
    let ast = parse(&tokens)?;
    Ok(optimize(ast))
}
