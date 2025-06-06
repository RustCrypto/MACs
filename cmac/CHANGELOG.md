# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.8.0 (UNRELEASED)
### Changed
- Edition changed to 2024 and MSRV bumped to 1.85
- Relax MSRV policy and allow MSRV bumps in patch releases
- Update to `digest` v0.11
- Update to `cipher` v0.5
- Replace type aliases with newtypes ([#186])

### Removed
- `std` crate feature ([#186])

[#186]: https://github.com/RustCrypto/MACs/pull/186

## 0.7.2 (2022-03-14)
### Changed
- Do not include large CAVP test vectors in published packages ([#128])

[#128]: https://github.com/RustCrypto/MACs/pull/128

## 0.7.1 (2022-02-17)
### Fixed
- Minimal versions build ([#108])

[#108]: https://github.com/RustCrypto/MACs/pull/108

## 0.7.0 (2022-02-10)
### Changed
- Migrate from `crypto-mac` dependency to `digest v0.10` ([#103])
- Bump `cipher` dependency to v0.4 ([#103])

[#103]: https://github.com/RustCrypto/MACs/pull/103

## 0.6.0 (2021-04-29)
### Changed
- Bump `crypto-mac` crate dependency to v0.11 ([#73])

[#73]: https://github.com/RustCrypto/MACs/pull/73

## 0.5.1 (2020-10-16)
### Added
- Zulip badge ([#64])

[#64]: https://github.com/RustCrypto/MACs/pull/64

## 0.5.0 (2020-10-16)
### Changed
- Bump `crypto-mac` dependency to v0.10 ([#62])

[#62]: https://github.com/RustCrypto/MACs/pull/62

## 0.4.0 (2020-08-12)
### Changed
- Bump `crypto-mac` dependency to v0.9, implement the `FromBlockCipher` trait ([#57])

[#57]: https://github.com/RustCrypto/MACs/pull/57

## 0.3.1 (2020-08-12)
### Added
- Implement `From<BlockCipher>` ([#54])
- Implement `io::Write` ([#55])

[#54]: https://github.com/RustCrypto/MACs/pull/54
[#55]: https://github.com/RustCrypto/MACs/pull/55

## 0.3.0 (2020-06-06)
### Changed
- Bump `aes` crate dependency to v0.4 ([#40])
- Bump `dbl` crate dependency to v0.3 ([#39])
- Bump `crypto-mac` dependency to v0.8; MSRV 1.41+ ([#30])
- Rename `result` methods to `finalize` ([#38])
- Upgrade to Rust 2018 edition ([#30])

[#40]: https://github.com/RustCrypto/MACs/pull/40
[#39]: https://github.com/RustCrypto/MACs/pull/39
[#38]: https://github.com/RustCrypto/MACs/pull/38
[#30]: https://github.com/RustCrypto/MACs/pull/30

## 0.2.0 (2018-10-03)

## 0.1.0 (2017-11-26)
