#!/bin/bash

set -eux

# Test with the `insecure-soft` backend enabled
cargo test --package=polyval --all-features

# Test without `insecure-soft` but with PCLMULQDQ hardware intrinsics
RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+sse2,+sse4.1" cargo test --package polyval --tests

# Test with both `insecure-soft` and PCLMULQDQ hardware intrinsics (uses PCLMULQDQ)
RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+sse2,+sse4.1" cargo test --package polyval --all-features
