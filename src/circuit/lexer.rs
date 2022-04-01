use std::{iter::Peekable, str::Chars};

/// Represents a token produced by the lexer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Token {
    /// The ! token
    Bang,
    /// The & token
    Ampersand,
    /// The | token
    Bar,
    /// The = token
    Equal,
    /// The ^ token
    Caret,
    /// A ( token
    LParen,
    /// A ) token
    RParen,
    /// An input aX
    A(u32),
    /// An input bX
    B(u32),
}

impl Token {
    /// Return the input contained inside this token, if any.
    pub fn get_input(&self) -> Option<u32> {
        match self {
            Token::A(x) | Token::B(x) => Some(*x),
            _ => None,
        }
    }
}

/// Represents an error that can happen while lexing.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LexError {
    /// The lexer has seen an unexpected character.
    UnexpectedCharacter(char),
    /// We expected to see an index after the start of an input reference.
    ExpectedIndex,
}

struct Lexer<'a> {
    // We hold an iterator over all the characters in our string
    chars: Peekable<Chars<'a>>,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Lexer {
            chars: input.chars().peekable(),
        }
    }

    fn number(&mut self) -> u32 {
        let mut acc = 0u32;
        while let Some(d) = self.chars.peek().and_then(|x| x.to_digit(10)) {
            self.chars.next();
            acc = 10 * acc + d;
        }
        acc
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Result<Token, LexError>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(c) = self.chars.next() {
            match c {
                '!' => return Some(Ok(Token::Bang)),
                '&' => return Some(Ok(Token::Ampersand)),
                '|' => return Some(Ok(Token::Bar)),
                '=' => return Some(Ok(Token::Equal)),
                '^' => return Some(Ok(Token::Caret)),
                '(' => return Some(Ok(Token::LParen)),
                ')' => return Some(Ok(Token::RParen)),
                'a' => {
                    if !self.chars.peek().map_or(false, |x| x.is_digit(10)) {
                        return Some(Err(LexError::ExpectedIndex));
                    }
                    return Some(Ok(Token::A(self.number())));
                }
                'b' => {
                    if !self.chars.peek().map_or(false, |x| x.is_digit(10)) {
                        return Some(Err(LexError::ExpectedIndex));
                    }
                    return Some(Ok(Token::B(self.number())));
                }
                w if w.is_whitespace() => {}
                _ => return Some(Err(LexError::UnexpectedCharacter(c))),
            }
        }
        None
    }
}

/// Run the lexer on some input, producing a list of tokens, or an error.
pub fn lex(input: &str) -> Result<Vec<Token>, LexError> {
    let mut out = Vec::new();
    for token in Lexer::new(input) {
        out.push(token?);
    }
    Ok(out)
}
