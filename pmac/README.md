# RustCrypto: PMAC

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [Parallel Message Authentication Code (PMAC)][1].

[Documentation][docs-link]

## Minimum Supported Rust Version

Rust **1.81** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/pmac.svg?logo=rust
[crate-link]: https://crates.io/crates/pmac
[docs-image]: https://docs.rs/pmac/badge.svg
[docs-link]: https://docs.rs/pmac/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260044-MACs
[build-image]: https://github.com/RustCrypto/MACs/workflows/pmac/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/MACs/actions?query=workflow%3Apmac

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/PMAC_(cryptography)
