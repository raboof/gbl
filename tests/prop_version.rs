use gbl::{AppImage, Gbl};

/// Includes a binary or text file from the test data directory.
macro_rules! test_data {
    ( bytes $file:tt ) => {{
        &include_bytes!(concat!("../test-data/", $file))[..]
    }};
    ( array $file:tt ) => {{
        *include_bytes!(concat!("../test-data/", $file))
    }};
    ( str $file:tt ) => {
        include_str!(concat!("../test-data/", $file))
    };
}

/// Tests that an application properties version of 1.1 is accepted.
#[test]
fn create_gbl_1_1() {
    let bin = AppImage::parse(test_data!(bytes "1.1/1.1.bin")).unwrap();
    let gbl = Gbl::from_app_image(bin);
    let gbl = gbl.to_bytes();

    assert_eq!(gbl, &test_data!(bytes "1.1/1.1.gbl")[..]);
}
