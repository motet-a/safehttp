# safehttp

A slow (but simple, safe and strict) HTTP/1.1 parser for Rust.

Unlike many others HTTP parsers for Rust, this library focuses on
security and not on performance. We all know most of us don’t need
high-performance sub-microsecond SIMD-enabled event-driven zero-copy
HTTP parsing. We all know HTTP parser vulnerabilities [do](http://nginx.org/en/security_advisories.html)
[exist](https://httpd.apache.org/security/vulnerabilities_24.html) and
hide theirselves inside complexity. So the simpler the better.

Please review this code before using it. Feedbacks and other
contributions are highly appreciated.

## Usage

This parser uses types in the `http` crate.

[TODO]

## RFC 7230 compliance

For the sake of simplicity, this parser does not support optional and
seldomly used HTTP features like chunk trailers, chunk extensions or
exotic transfer encodings (other than `chunked`).

This parser is as strict as possible: things like non standard line
endings (i.e. not `CRLF`) are rejected.

However, this parser aims to be entirely compliant to the specification
and should work without any trouble with most user agents.

## Fuzzing

TODO

## Automated testing

TODO

## HTTP/2 and HTTP/3 support

HTTP/2 is currently not supported but could be added in the future. I’m not
actually against HTTP/2 but it is currently not as widely supported as
HTTP/1.1 and for a server, most clients will send HTTP/1.1 requests
before upgrading. So HTTP/1.1 parsing is required in anyway.

HTTP/3 seems to be widly different than HTTP/2 and HTTP/1, so it’s probably
better to support it in a different library.

## TODO

  - Write more tests. There are tests but more is always better.

  - Try to rewrite the parser with nom. The current implementation of the
    lookahead isn’t particularly beautiful.

