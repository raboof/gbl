extern crate gbl;

use gbl::Gbl;

macro_rules! fuzz_regression_tests {
	( $($filename:ident => $e:expr,)+ ) => {
		$(
			#[test]
			fn $filename() {
				let $filename = include_bytes!(concat!("fuzz-data/", stringify!($filename)));
				$e;
			}
		)+
	};
}

fuzz_regression_tests! {
    // This file contains a tag with a very large length, which could lead to OOM conditions.
    oom1 => assert!(Gbl::parse(oom1).unwrap_err().to_string().contains("size limit")),
}
