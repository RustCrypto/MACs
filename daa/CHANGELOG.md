# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (2020-08-12)
### Changed
- Bump `crypto-mac` dependency to v0.9, implement the `FromBlockCipher` trait ([#57])

[#57]: https://github.com/RustCrypto/MACs/pull/57

## 0.2.0 (2020-06-08)
### Changed
- Bump `daa` crate to v0.4 release ([#43])
- Bump `crypto-mac` dependency to v0.8; MSRV 1.41+ ([#32])
- Rename `result` methods to `finalize` ([#38])
- Upgrade to Rust 2018 edition ([#32])

[#43]: https://github.com/RustCrypto/MACs/pull/43
[#38]: https://github.com/RustCrypto/MACs/pull/38
[#32]: https://github.com/RustCrypto/MACs/pull/32

## 0.1.0 (2018-11-14)
- Initial release
