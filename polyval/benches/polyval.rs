#![feature(test)]
#[macro_use]
extern crate crypto_mac;
extern crate polyval;

use crypto_mac::generic_array::{typenum::U16, GenericArray};
use crypto_mac::MacResult;
use polyval::{Block, Polyval};
use std::{cmp::min, convert::TryInto};

bench!(PolyvalMac);

/// POLYVAL isn't a traditional MAC and for that reason doesn't impl the
/// `crypto_mac::Mac` trait.
///
/// This type is a newtype that impls a pseudo-MAC to leverage the benchmark
/// functionality.
///
/// This is just for benchmarking! Don't copy and paste this into your program
/// unless you really know what you're doing!!!
#[derive(Clone)]
struct PolyvalMac {
    poly: Polyval,
    leftover: usize,
    buffer: Block,
}

impl Mac for PolyvalMac {
    type OutputSize = U16;
    type KeySize = U16;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> PolyvalMac {
        let poly = Polyval::new(key.as_slice().try_into().unwrap());

        PolyvalMac {
            poly,
            leftover: 0,
            buffer: Block::default(),
        }
    }

    fn input(&mut self, data: &[u8]) {
        let mut m = data;

        if self.leftover > 0 {
            let want = min(16 - self.leftover, m.len());

            for (i, byte) in m.iter().cloned().enumerate().take(want) {
                self.buffer[self.leftover + i] = byte;
            }

            m = &m[want..];
            self.leftover += want;

            if self.leftover < 16 {
                return;
            }

            self.block();
            self.leftover = 0;
        }

        while m.len() >= 16 {
            self.block();
            m = &m[16..];
        }

        self.buffer[..m.len()].copy_from_slice(m);
        self.leftover = m.len();
    }

    fn reset(&mut self) {
        unimplemented!();
    }

    fn result(self) -> MacResult<Self::OutputSize> {
        let tag: Block = self.poly.result().into();
        MacResult::new(tag.into())
    }
}

impl PolyvalMac {
    /// Input the current internal buffer into POLYVAL
    fn block(&mut self) {
        let elem = self.buffer;
        self.poly.input_block(elem)
    }
}
