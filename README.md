# RustCrypto: Message Authentication Codes ![Rust Version][rustc-image] [![Project Chat][chat-image]][chat-link]

Collection of [Message Authentication Code][1] (MAC) algorithms written in pure Rust.

## Crates

| Name   | Algorithm | Crates.io     | Documentation | Build Status |
|--------|-----------|---------------|---------------|--------------|
| `cmac` | [CMAC]    | [![crates.io](https://img.shields.io/crates/v/cmac.svg)](https://crates.io/crates/cmac) | [![Documentation](https://docs.rs/cmac/badge.svg)](https://docs.rs/cmac) | [![Build](https://github.com/RustCrypto/MACs/workflows/cmac/badge.svg?branch=master&event=push)](https://github.com/RustCrypto/MACs/actions?query=workflow:cmac+branch:master)
| `daa`  | [DAA]     | [![crates.io](https://img.shields.io/crates/v/daa.svg)](https://crates.io/crates/daa) | [![Documentation](https://docs.rs/daa/badge.svg)](https://docs.rs/daa) | [![Build](https://github.com/RustCrypto/MACs/workflows/daa/badge.svg?branch=master&event=push)](https://github.com/RustCrypto/MACs/actions?query=workflow:daa+branch:master)
| `hmac` | [HMAC]    | [![crates.io](https://img.shields.io/crates/v/hmac.svg)](https://crates.io/crates/hmac) | [![Documentation](https://docs.rs/hmac/badge.svg)](https://docs.rs/hmac) | [![Build](https://github.com/RustCrypto/MACs/workflows/hmac/badge.svg?branch=master&event=push)](https://github.com/RustCrypto/MACs/actions?query=workflow:hmac+branch:master)
| `pmac` | [PMAC]    | [![crates.io](https://img.shields.io/crates/v/pmac.svg)](https://crates.io/crates/pmac) | [![Documentation](https://docs.rs/pmac/badge.svg)](https://docs.rs/pmac) | [![Build](https://github.com/RustCrypto/MACs/workflows/pmac/badge.svg?branch=master&event=push)](https://github.com/RustCrypto/MACs/actions?query=workflow:pmac+branch:master)

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license

[//]: # (badges)

[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260044-MACs

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/Message_authentication_code

[//]: # (algorithms)

[CMAC]: https://en.wikipedia.org/wiki/One-key_MAC
[DAA]: https://en.wikipedia.org/wiki/Data_Authentication_Algorithm
[HMAC]: https://en.wikipedia.org/wiki/HMAC
[PMAC]: https://en.wikipedia.org/wiki/PMAC_(cryptography)

