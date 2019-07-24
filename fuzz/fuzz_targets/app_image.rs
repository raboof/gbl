#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate gbl;

use gbl::{AppImage, Gbl, P256KeyPair};

#[rustfmt::skip] // FIXME: https://github.com/rust-lang/rustfmt/issues/3234
fuzz_target!(|data: &[u8]| {

	if let Ok(app_img) = AppImage::parse(data) {
	    let keypair = P256KeyPair::from_pem(include_str!("../../test-data/signing-key")).unwrap();
        if let Ok(app_img) = app_img.sign(&keypair) {
            assert!(app_img.is_signed());
            Gbl::from_app_image(app_img).to_bytes();
        }
	}
    
});
