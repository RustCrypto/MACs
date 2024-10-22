# RustCrypto: Message Authentication Codes

[![Project Chat][chat-image]][chat-link]
[![dependency status][deps-image]][deps-link]
![Apache2/MIT licensed][license-image]

Collection of [Message Authentication Code][1] (MAC) algorithms written in pure Rust.

## Supported Algorithms

| Algorithm    | Crate          | Crates.io | Documentation | MSRV |
|--------------|----------------|:---------:|:-------------:|:----:|
| [BelT MAC]   | [`belt-mac`]   |   [![crates.io](https://img.shields.io/crates/v/belt-mac.svg)](https://crates.io/crates/belt-mac)   |   [![Documentation](https://docs.rs/belt-mac/badge.svg)](https://docs.rs/belt-mac)   | ![MSRV 1.57][msrv-1.57] |
| [CBC-MAC]    | [`cbc-mac`]    |    [![crates.io](https://img.shields.io/crates/v/cbc-mac.svg)](https://crates.io/crates/cbc-mac)    |    [![Documentation](https://docs.rs/cbc-mac/badge.svg)](https://docs.rs/cbc-mac)    | ![MSRV 1.81][msrv-1.56] |
| [CMAC]       | [`cmac`]       |       [![crates.io](https://img.shields.io/crates/v/cmac.svg)](https://crates.io/crates/cmac)       |       [![Documentation](https://docs.rs/cmac/badge.svg)](https://docs.rs/cmac)       | ![MSRV 1.81][msrv-1.56] |
| [HMAC]       | [`hmac`]       |       [![crates.io](https://img.shields.io/crates/v/hmac.svg)](https://crates.io/crates/hmac)       |       [![Documentation](https://docs.rs/hmac/badge.svg)](https://docs.rs/hmac)       | ![MSRV 1.41][msrv-1.41] |
| [PMAC]       | [`pmac`]       |       [![crates.io](https://img.shields.io/crates/v/pmac.svg)](https://crates.io/crates/pmac)       |       [![Documentation](https://docs.rs/pmac/badge.svg)](https://docs.rs/pmac)       | ![MSRV 1.81][msrv-1.56] |
| [Retail MAC] | [`retail-mac`] | [![crates.io](https://img.shields.io/crates/v/retail-mac.svg)](https://crates.io/crates/retail-mac) | [![Documentation](https://docs.rs/retail-mac/badge.svg)](https://docs.rs/retail-mac) | ![MSRV 1.81][msrv-1.56] |

### Minimum Supported Rust Version (MSRV) Policy

MSRV bumps are considered breaking changes and will be performed only with minor version bump.

## License

All crates licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260044-MACs
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[deps-image]: https://deps.rs/repo/github/RustCrypto/MACs/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/MACs
[msrv-1.41]: https://img.shields.io/badge/rustc-1.41.0+-blue.svg
[msrv-1.81]: https://img.shields.io/badge/rustc-1.56.0+-blue.svg
[msrv-1.57]: https://img.shields.io/badge/rustc-1.57.0+-blue.svg

[//]: # (crates)

[`belt-mac`]: ./belt-mac
[`cbc-mac`]: ./cbc-mac
[`cmac`]: ./cmac
[`hmac`]: ./hmac
[`pmac`]: ./pmac
[`retail-mac`]: ./retail-mac

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/Message_authentication_code

[//]: # (algorithms)

[BelT MAC]: https://apmi.bsu.by/assets/files/std/belt-spec371.pdf
[CBC-MAC]: https://en.wikipedia.org/wiki/CBC-MAC
[CMAC]: https://en.wikipedia.org/wiki/One-key_MAC
[HMAC]: https://en.wikipedia.org/wiki/HMAC
[PMAC]: https://en.wikipedia.org/wiki/PMAC_(cryptography)
[Retail MAC]: https://en.wikipedia.org/wiki/ISO/IEC_9797-1#MAC_algorithm_3
