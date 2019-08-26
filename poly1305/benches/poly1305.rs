#![feature(test)]
#[macro_use]
extern crate crypto_mac;
extern crate poly1305;

use crypto_mac::generic_array::{
    typenum::{U16, U32},
    GenericArray,
};
use crypto_mac::MacResult;
use poly1305::{Poly1305, Block};
use std::convert::TryInto;

bench!(Poly1305Mac);

/// Poly1305 isn't a traditional MAC and for that reason doesn't impl the
/// `crypto_mac::Mac` trait.
///
/// This type is a newtype that impls a pseudo-MAC to leverage the benchmark
/// functionality.
///
/// This is just for benchmarking! Don't copy and paste this into your program
/// unless you really know what you're doing!!!
#[derive(Clone)]
struct Poly1305Mac(Poly1305);

impl Mac for Poly1305Mac {
    type OutputSize = U16;
    type KeySize = U32;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Poly1305Mac {
        let poly = Poly1305::new(key.as_slice().try_into().unwrap());
        Poly1305Mac(poly)
    }

    fn input(&mut self, data: &[u8]) {
        self.0.input(data);
    }

    fn reset(&mut self) {
        unimplemented!();
    }

    fn result(self) -> MacResult<Self::OutputSize> {
        let tag: Block = self.0.result().into();
        MacResult::new(tag.into())
    }
}
