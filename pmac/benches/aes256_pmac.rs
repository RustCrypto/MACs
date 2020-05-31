#![feature(test)]

crypto_mac::bench!(pmac::Pmac::<aes::Aes256>);
