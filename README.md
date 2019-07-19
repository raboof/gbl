# GBL Firmware file manipulation library

[![crates.io](https://img.shields.io/crates/v/gbl.svg)](https://crates.io/crates/gbl)
[![docs.rs](https://docs.rs/gbl/badge.svg)](https://docs.rs/gbl/)
[![Build Status](https://travis-ci.org/dac-gmbh/gbl.svg?branch=master)](https://travis-ci.org/dac-gmbh/gbl)

Rust library for reading, creating and manipulating `.gbl` firmware update
files.

Also check out [this blog post] for a gentle introduction into the
crate's typestate-based API.

[this blog post]: https://blog.1aim.com/post/gbl-release/

## Features

* Creating GBL files from raw application images
* Parsing existing GBL files
* Encrypt and sign GBL files
* Decrypt GBL files and verify the embedded signature
* Signing application images for secure boot
* A simple command-line tool wrapping the library

### Not yet supported

* Bootloader image
* Custom metadata sections

## Command-line Usage

The command-line tool `gbl` can be installed by running `cargo install` in this
directory. If you don't want to install it, you can also run it using
`cargo run`. In that case, replace the `gbl` command with `cargo run --` (for
example, `cargo run -- create --help`).

The tool currently supports the following operations:

```
SUBCOMMANDS:
    app-image    Raw application image manipulation.
    create       Create a GBL file from raw application data.
    decrypt      Decrypts an encrypted GBL file with a shared AES key.
    dump         Parses an existing GBL file and dumps its structure to the console.
    encrypt      GBL firmware file handling library
    help         Prints this message or the help of the given subcommand(s)
    sign         Sign a GBL file using a private ECDSA key.
    verify       Verifies the signature of a signed GBL file.
```

## Development

### Fuzzing

You can run the included fuzzing targets (`gbl` or `app_image`) using

    cargo +nightly fuzz run gbl

By default, libFuzzer won't produce inputs larger than 4096 bytes. To remedy
this, use this command instead (you can use any max length you want, of course):

    cargo +nightly fuzz run gbl -- -max_len=100000

Note that fuzz targets are not tested on CI and might break from time to time as
the API changes. Feel free to fix them if this happens!

### Benchmarks

Benchmarks use [criterion](https://github.com/japaric/criterion.rs) and should
be straighforward. Just do `cargo bench`.

### Flame Graph

To generate a flame graph for a specific benchmark:

```
perf record --call-graph=dwarf target/release/deps/bench-<HASH> --measure-only '<BENCHMARK NAME>'
perf script | stackcollapse-perf.pl | flamegraph.pl > flame.svg
```

Make sure to use the same `<HASH>` Cargo displays when doing `cargo bench`.
