use cipher::{Block, BlockSizeUser};

#[inline(always)]
pub(crate) fn get_u32(block: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(block[4 * i..][..4].try_into().unwrap())
}

#[inline(always)]
pub(crate) fn set_u32(block: &mut [u8], val: &[u32; 4], i: usize) {
    block[4 * i..][..4].copy_from_slice(&val[i].to_le_bytes());
}

#[inline(always)]
pub(crate) fn phi1<C>(u: &Block<C>) -> Block<C>
where
    C: BlockSizeUser,
{
    let u1 = get_u32(u, 0);
    let u2 = get_u32(u, 1);
    let u3 = get_u32(u, 2);
    let u4 = get_u32(u, 3);
    let v = [u2, u3, u4, u1 ^ u2];
    let mut block = Block::<C>::default();
    set_u32(&mut block, &v, 0);
    set_u32(&mut block, &v, 1);
    set_u32(&mut block, &v, 2);
    set_u32(&mut block, &v, 3);
    block
}

#[inline(always)]
pub(crate) fn phi2<C>(u: &Block<C>) -> Block<C>
where
    C: BlockSizeUser,
{
    let u1 = get_u32(u, 0);
    let u2 = get_u32(u, 1);
    let u3 = get_u32(u, 2);
    let u4 = get_u32(u, 3);
    let v = [u1 ^ u4, u1, u2, u3];
    let mut block = Block::<C>::default();
    set_u32(&mut block, &v, 0);
    set_u32(&mut block, &v, 1);
    set_u32(&mut block, &v, 2);
    set_u32(&mut block, &v, 3);
    block
}
