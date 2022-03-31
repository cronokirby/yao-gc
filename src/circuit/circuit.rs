pub use super::ast::Input;

/// Represents a boolean circuit, over the respective inputs of both parties.
#[derive(Clone, Debug)]
enum Circuit {
    /// Represents one of the inputs of the parties.
    Input(Input),
    /// Represents an arbitrary gate taking in two wires.
    ///
    /// A boolean function on two inputs as 16 possible outputs, so 4 bits are
    /// sufficient to specify it, one for each of the possible input pairs.
    /// We use the low 4 bits of a u8 to specify that.
    Gate(u8, Box<Circuit>, Box<Circuit>),
}
