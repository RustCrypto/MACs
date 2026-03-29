//! Test vectors from: <http://web.cs.ucdavis.edu/~rogaway/ocb/pmac-test.htm>

use aes::{Aes128, Aes192, Aes256};
use digest::{dev::reset_mac_test, new_mac_test};
use pmac::Pmac;

new_mac_test!(pmac_aes128, Pmac<Aes128>, reset_mac_test);
new_mac_test!(pmac_aes192, Pmac<Aes192>, reset_mac_test);
new_mac_test!(pmac_aes256, Pmac<Aes256>, reset_mac_test);
