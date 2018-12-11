#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate gbl;

use gbl::Gbl;

#[rustfmt::skip] // FIXME: https://github.com/rust-lang/rustfmt/issues/3234
fuzz_target!(|data: &[u8]| {

	if let Ok(gbl) = Gbl::parse(data) {
		gbl.to_bytes();
	}

});
