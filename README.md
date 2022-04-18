# yao-gc

![](./cover.png)

This is a rudimentary implementation of [Yao's Garbled Circuits](https://www.wikiwand.com/en/Garbled_circuit). This is a technique which allows two
parties to evaluate a boolean function on their private inputs, without
revealing those inputs to eachother.

This is a special case of Multiparty-Computation, in the case of 2 parties
which are semi-honest. By semi-honest, we mean that both parties will follow
the protocol, and won't send malicious inputs in an attempt to derail it.

This implementation provides a LISP-y DSL for describing circuits, and
implements a simple command line program which runs the protocol by
communicating over TCP.

# Usage

```txt
yao-gc 0.1.0

USAGE:
    yao-gc [FLAGS] <ADDRESS> --circuit <circuit>

FLAGS:
    -h, --help       Prints help information
    -l, --listen     If true, then this will be the garbler listening for connections
    -V, --version    Prints version information

OPTIONS:
    -c, --circuit <circuit>    The path to the circuit file

ARGS:
    <ADDRESS>    The network address to listen on, or to connect to
```

As an example, consider having a simple and circuit in the file `circuit.txt`:

```txt
(& a0 b0)
```

This calculates the and operation between A's first input, and B's first input.

A will go first:

```txt
$ yao-gc --listen --circuit circuit.txt localhost:1234
input:
1
```

Then B will go second, connecting to the port that A is listening on:

```txt
$ yao-gc --circuit circuit.txt localhost:1234
input:
0
false
```

A will also print `false`, since they receive the result after running the
protocol as well.

The number of input bits is determined by the maximum input the circuit
uses for that respective party. So if the circuit contains `a2` as the
largest input, then A will need to supply 3 bits, for `a0`, `a1`, and `a2`.

# Circuit Language

The language is very simple. A program is a single boolean expression, which
is either:

- An input, like `a0`, or `b0`
- A unary operator `(! <expr>)`
- A binary operator `(<op> <expr> <expr>)`

## Inputs

Each input starts with either `a`, or `b`, and then the index of the input
(zero-based). Inputs starting with `a` denote party A, or the one
listening for a connection, and inputs starting with `b` denote the other
party, which initiates the connection.

## Unary Operators

There's a single unary operation `!`, which negates a boolean value.

## Binary Operators

There are currently 4 supported binary operators:

- `&` the and operator
- `|` the or operator
- `^` the xor operator
- `=` the equals operator

These, combined with `!`, are sufficient to implement every boolean operation.

## Examples

Examples can be found in the `/examples` directory of this repository.

# Limitations

- Only a single output is supported at the moment.

This isn't a fundamental
limitation of garbled circuits, just of this implementation. This could
easily be amended

- The protocol only works for two parties
- The protocol isn't maliciously secure

This are limitations of the protocol being implemented, not this implementation.
