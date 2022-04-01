use super::ast;
pub use super::ast::Input;

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
pub fn optimize(ast: ast::AST) -> Circuit {
    use ast::Gate1::*;
    use ast::AST::*;

    match ast {
        Input(_) => todo!(),
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
