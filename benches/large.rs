extern crate gbl;
#[macro_use]
extern crate criterion;

use criterion::{Bencher, Benchmark, Criterion, Throughput};
use gbl::{AesKey, AppImage, Gbl, P256KeyPair};

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
    let large = test_data!(bytes "large/large.gbl");
    let parse = |data| move |b: &mut Bencher| b.iter(|| Gbl::parse(data).unwrap());
    c.bench(
        "parse large.gbl",
        Benchmark::new("parse large.gbl", parse(large))
            .throughput(Throughput::Bytes(large.len() as u32))
            .sample_size(20),
    );
}

fn from_bin(c: &mut Criterion) {
    let data = test_data!(bytes "large/large.bin");
    c.bench_function("from_app_image large.bin", move |b| {
        b.iter(|| Gbl::from_app_image(AppImage::parse(data).unwrap()))
    });
}

fn write(c: &mut Criterion) {
    let bytes = test_data!(bytes "large/large.gbl");
    c.bench(
        "write large.gbl",
        Benchmark::new("write large.gbl", move |b| {
            let gbl = Gbl::parse(bytes).unwrap();
            b.iter(|| {
                // This also measures the vec allocation, but that shouldn't be a
                // problem.
                let mut buf = vec![0; 1024 * 1024 * 10];
                gbl.write(&mut buf[..]).unwrap();
                buf
            })
        })
        .throughput(Throughput::Bytes(bytes.len() as u32))
        .sample_size(20),
    );
}

fn sign_encrypt(c: &mut Criterion) {
    let data = test_data!(bytes "large/large.gbl");
    let key = P256KeyPair::from_pem(test_data!(str "signing-key")).unwrap();
    let gbl = Gbl::parse(data).unwrap();
    let gbl = gbl.into_not_signed().unwrap().into_not_encrypted().unwrap();
    let gbl2 = gbl.clone().into_owned();
    c.bench(
        "sign large.gbl",
        Benchmark::new("sign large.gbl", move |b| {
            b.iter(|| gbl2.clone().sign(&key).unwrap())
        })
        .throughput(Throughput::Bytes(data.len() as u32))
        .sample_size(20),
    );
    c.bench(
        "encrypt large.gbl",
        Benchmark::new("encrypt large.gbl", move |b| {
            b.iter(|| {
                gbl.clone().encrypt(AesKey::from_raw([
                    0x5b, 0x69, 0x41, 0x78, 0xba, 0xa2, 0xc3, 0x6c, 0x63, 0x20, 0x65, 0xd5, 0xbe,
                    0xec, 0xaa, 0x3f,
                ]))
            })
        })
        .throughput(Throughput::Bytes(data.len() as u32))
        .sample_size(40),
    );
}

criterion_group!(benches, parse, from_bin, write, sign_encrypt);
criterion_main!(benches);
