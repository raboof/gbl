extern crate gbl;
#[macro_use]
extern crate criterion;

use criterion::{Bencher, Benchmark, Criterion, Throughput};
use gbl::{AppImage, Gbl, P256KeyPair};

/// Includes a binary or text file from the test data directory.
macro_rules! test_data {
    ( bytes $file:tt ) => {
        &include_bytes!(concat!("../test-data/", $file))[..]
    };
    ( str $file:tt ) => {
        include_str!(concat!("../test-data/", $file))
    };
}

fn parse(c: &mut Criterion) {
    let parse = |data| move |b: &mut Bencher| b.iter(|| Gbl::parse(data).unwrap());
    c.bench_function(
        "parse empty.gbl",
        parse(test_data!(bytes "empty/empty.gbl")),
    );
    c.bench_function(
        "parse empty-encrypted.gbl",
        parse(test_data!(bytes "empty/empty-encrypted.gbl")),
    );
    c.bench_function(
        "parse empty-signed.gbl",
        parse(test_data!(bytes "empty/empty-signed.gbl")),
    );
    c.bench_function(
        "parse empty-signed-encrypted.gbl",
        parse(test_data!(bytes "empty/empty-signed-encrypted.gbl")),
    );
}

fn from_bin(c: &mut Criterion) {
    c.bench_function("from_app_image empty.bin", |b| {
        b.iter(|| {
            Gbl::from_app_image(AppImage::parse(test_data!(bytes "empty/empty.bin")).unwrap())
        })
    });
}

fn write(c: &mut Criterion) {
    let bytes = test_data!(bytes "empty/empty.gbl");
    c.bench(
        "write empty.gbl",
        Benchmark::new("write empty.gbl", move |b| {
            let gbl = Gbl::parse(bytes).unwrap();
            b.iter(|| {
                // This also measures the vec allocation, but that shouldn't be a
                // problem.
                let mut buf = vec![0; 1024];
                gbl.write(&mut buf[..]).unwrap();
                buf
            })
        })
        .throughput(Throughput::Bytes(bytes.len() as u64))
        .sample_size(20),
    );
}

fn sign_encrypt(c: &mut Criterion) {
    let gbl = Gbl::from_app_image(AppImage::parse(test_data!(bytes "empty/empty.gbl")).unwrap());
    let key = P256KeyPair::from_pem(test_data!(str "signing-key")).unwrap();
    c.bench_function("sign empty.gbl", move |b| {
        b.iter(|| gbl.clone().sign(&key).unwrap())
    });
}

criterion_group!(benches, parse, from_bin, write, sign_encrypt);
criterion_main!(benches);
