use std::{error::Error, fmt};

use super::lexer::Token;

/// Represents an initial input to the circuit.
///
/// The inputs to the circuit either come from player A, or from player B.
///
/// We use a u32 as an index, representing the ith input of that player to the circuit.
#[derive(Clone, Copy, Debug, PartialEq)]
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
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Gate1 {
    Not,
}

/// Represents a gate taking in two inputs, expressible in our syntax.
///
/// Not all gates are included here, just the ones we have in the language.
#[derive(Clone, Copy, Debug, PartialEq)]
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
#[derive(Clone, Debug, PartialEq)]
pub enum AST {
    /// An input to the circuit.
    Input(Input),
    /// A gate taking in one input.
    Gate1(Gate1, Box<AST>),
    /// A gate taking in two inputs.
    Gate2(Gate2, Box<AST>, Box<AST>),
}

peg::parser! {
    grammar ast_parser() for [Token] {
        use Token::*;

        rule input() -> super::Input
            = n:$[A(_)] { super::Input::A(n[0].get_input().unwrap()) }
            / n:$[B(_)] { super::Input::B(n[0].get_input().unwrap()) }

        rule gate1() -> Gate1
          = [Bang] { Gate1::Not }

        rule gate2() -> Gate2
          = [Bar] { Gate2::Or }
          / [Ampersand] { Gate2::And }
          / [Equal] { Gate2::Equal }
          / [Caret] { Gate2::Xor }

        pub rule ast() -> AST
            = i:input() { AST::Input(i) }
            / [LParen] g:gate1() a:ast() [RParen] { AST::Gate1(g, Box::new(a)) }
            / [LParen] g:gate2() a1:ast() a2:ast() [RParen] { AST::Gate2(g, Box::new(a1), Box::new(a2)) }
    }
}

/// Represents the type of error that can occurr while parsing
///
/// This is an opaque type, and should be presented to the user directly, more or less.
/// There's no way to recover from a parse error, with this compiler architecture, anyways.
#[derive(Debug, PartialEq)]
pub struct ParseError(peg::error::ParseError<usize>);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for ParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl From<peg::error::ParseError<usize>> for ParseError {
    fn from(e: peg::error::ParseError<usize>) -> Self {
        ParseError(e)
    }
}

/// Parse a string into our AST.
///
/// This can fail if the string doesn't match the syntax of our language.
pub fn parse(input: &[Token]) -> Result<AST, ParseError> {
    ast_parser::ast(input).map_err(|x| x.into())
}

#[cfg(test)]
mod test {
    use super::super::lexer::lex;
    use super::*;

    /// Assert that a string correctly parses to a given AST
    macro_rules! assert_parse {
        ($a:expr, $b:expr) => {{
            let tokens = lex($a);
            assert!(tokens.is_ok());
            let tokens = tokens.unwrap();
            let res = parse(&tokens);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), $b);
        }};
    }

    #[test]
    fn parsing_inputs() {
        assert_parse!("a0", AST::Input(Input::A(0)));
        assert_parse!("b10", AST::Input(Input::B(10)));
    }

    #[test]
    fn parsing_gates() {
        assert_parse!(
            "(& a0 b0)",
            AST::Gate2(
                Gate2::And,
                Box::new(AST::Input(Input::A(0))),
                Box::new(AST::Input(Input::B(0)))
            )
        );
        assert_parse!(
            "(| a0 b0)",
            AST::Gate2(
                Gate2::Or,
                Box::new(AST::Input(Input::A(0))),
                Box::new(AST::Input(Input::B(0)))
            )
        );
        assert_parse!(
            "(^ a0 b0)",
            AST::Gate2(
                Gate2::Xor,
                Box::new(AST::Input(Input::A(0))),
                Box::new(AST::Input(Input::B(0)))
            )
        );
        assert_parse!(
            "(= a0 b0)",
            AST::Gate2(
                Gate2::Equal,
                Box::new(AST::Input(Input::A(0))),
                Box::new(AST::Input(Input::B(0)))
            )
        );
        assert_parse!(
            "(! a0)",
            AST::Gate1(Gate1::Not, Box::new(AST::Input(Input::A(0))),)
        );
    }

    #[test]
    fn parsing_nested_gate() {
        assert_parse!(
            "(& a0 (& a1 a2))",
            AST::Gate2(
                Gate2::And,
                Box::new(AST::Input(Input::A(0))),
                Box::new(AST::Gate2(
                    Gate2::And,
                    Box::new(AST::Input(Input::A(1))),
                    Box::new(AST::Input(Input::A(2)))
                ))
            )
        );
    }
}
