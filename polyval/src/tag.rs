//! POLYVAL authentication tags

use subtle::{Choice, ConstantTimeEq};
use Block;

/// POLYVAL authentication tags
pub struct Tag(Block);

impl Tag {
    /// Create a new POLYVAL authentication tag
    pub(crate) fn new(tag: Block) -> Self {
        Tag(tag)
    }
}

impl AsRef<Block> for Tag {
    fn as_ref(&self) -> &Block {
        &self.0
    }
}

impl ConstantTimeEq for Tag {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(other.0.as_ref())
    }
}

impl From<Tag> for Block {
    fn from(tag: Tag) -> Block {
        tag.0
    }
}
