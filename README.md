# RDF::LMDB - Lightweight, persistent, transactional RDF store

This library implements `RDF::Repository` using the Symas Lightning
MDB key-value database. It is intended to be a basic, durable,
locally-attached quad store, that avails itself of the properties of
LMDB.

`RDF::LMDB` is _also_ intended to provide a reference implementation
of an architecture for storing RDF in _any_ key-value database, such
that this adapter could be ported, or indeed the data _imported_, to
other back-ends (e.g. Berkeley DB, LevelDB, Kyoto Cabinet…) without
having to significantly change the design. The only real requirement
for the back-end is some kind of cursor functionality, and the
handling of multi-valued keys.

## Architecture

The system uses binary SHA-256 digests of N-Triples representations of
terms and statements. Terms are normalized first before being hashed.
The hashes themselves are stored in their binary representation.

### Triples

The main content of the store is keyed on the hash of a normalized
N-Triples statement (including the terminating ` .`). Its values are
the concatenated hashes of the individual terms:

    sha256(s <sp> p <sp> o " .") => sha256(s) sha256(p) sha256(o)

### GSPO

There are four indices that resolve terms to statements, _graph_,
_subject_, _predicate_, _object_, respectively:

    sha256(term) => sha256(s <sp> p <sp> o " .")

### Node Resolution

Finally, there is an index that maps the digests of the terms back to
their normalized N-Triples representations:

    sha256(term) => term

## API Documentation

Generated and deposited
[in the usual place](http://www.rubydoc.info/gems/rdf-lmdb/).

## Installation

Come on, you know how to do this:

    $ gem install rdf-lmdb

Or, [download it off rubygems.org](https://rubygems.org/gems/rdf-lmdb).

## Contributing

Bug reports and pull requests are welcome at
[the GitHub repository](https://github.com/doriantaylor/rb-rdf-sak).

## Copyright & License

©2019 [Dorian Taylor](https://doriantaylor.com/)

This software is provided under
the [Apache License, 2.0](https://www.apache.org/licenses/LICENSE-2.0).
