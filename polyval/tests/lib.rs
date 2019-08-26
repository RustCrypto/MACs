#[macro_use]
extern crate hex_literal;
extern crate polyval;

use polyval::{Block, Polyval};

//
// Test vectors or POLYVAL from RFC 8452 Appendix A
// <https://tools.ietf.org/html/rfc8452#appendix-A>
//

const H: Block = hex!("25629347589242761d31f826ba4b757b");
const X_1: Block = hex!("4f4f95668c83dfb6401762bb2d01a262");
const X_2: Block = hex!("d1a24ddd2721d006bbe45f20d3c9f362");

/// POLYVAL(H, X_1, X_2)
const POLYVAL_RESULT: Block = hex!("f7a3b47b846119fae5b7866cf5e5b77e");

#[test]
fn rfc_8452_test_vector() {
    let result = Polyval::new(H).chain_block(X_1).chain_block(X_2).result();
    assert_eq!(result.as_ref(), &POLYVAL_RESULT);
}
