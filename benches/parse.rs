#[macro_use]
extern crate criterion;

use criterion::Criterion;

extern crate safehttp;

use std::io;

fn concat(bytes_list: Vec<&[u8]>) -> Vec<u8> {
    bytes_list
        .iter()
        .flat_map(|b| b.to_vec())
        .collect()
}

fn concat_lines(bytes_list: Vec<&[u8]>) -> Vec<u8> {
    bytes_list
        .iter()
        .flat_map(|b| concat(vec![b, b"\r\n"]))
        .collect()
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("parse request", |b| {
        let source = concat_lines(vec![
            b"POST /foo/bar?some=parameters#anchor HTTP/1.1",
            b"Host: example.com",
            b"X-Some-Header: foo",
            b"Connection: close",
            b"Content-Type: text/plain",
            b"Last-Modified: Thu, 02 Jun 2016 06:01:08 GMT",
            b"Server: rust_http_parser",
            b"Set-Cookie: this is an HTTP parser the quick brown fox jumps over the lazy dog",
            b"Content-Length: 8",
            b"",
            b"httphttp",
        ]);

        b.iter(move || {
            let mut cursor = io::Cursor::new(&source);
            let config = &safehttp::Config::DEFAULT;
            safehttp::parse_request(cursor, config).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

