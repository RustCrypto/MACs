/// The number of bytes required to write a number in the KMAC encoded format, excluding the
/// leading byte that indicates the length of the encoding.
#[inline(always)]
pub(crate) fn num_encoding_size(num: u64) -> usize {
    let bits = 64 - (num | 1).leading_zeros() as usize;
    bits.div_ceil(8)
}

#[inline(always)]
pub(crate) fn left_encode(num: u64, buffer: &mut [u8; 9]) -> &[u8] {
    let encoding_size = num_encoding_size(num);
    buffer[0] = encoding_size as u8;
    buffer[1..=encoding_size].copy_from_slice(&num.to_be_bytes()[8 - encoding_size..]);
    &buffer[..=encoding_size]
}

#[inline(always)]
pub(crate) fn right_encode(num: u64, buffer: &mut [u8; 9]) -> &[u8] {
    let encoding_size = num_encoding_size(num);
    buffer[0..encoding_size].copy_from_slice(&num.to_be_bytes()[8 - encoding_size..]);
    buffer[encoding_size] = encoding_size as u8;
    &buffer[..=encoding_size]
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn test_num_encoding_size() {
        // sha3::block_api::Sha3ReaderCore::<sha3::Sha3_256>::new(&[0; 200]);
        let test_cases = [
            (0, 1),
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 1),
            (5, 1),
            (6, 1),
            (7, 1),
            (8, 1),
            (9, 1),
            (10, 1),
            (255, 1),
            (256, 2),
            (257, 2),
            (65535, 2),
            (65536, 3),
            (65537, 3),
            (16777215, 3),
            (16777216, 4),
            (16777217, 4),
        ];

        for &(num, expected_size) in &test_cases {
            assert_eq!(
                num_encoding_size(num),
                expected_size,
                "num_encoding_size({}) should return {}",
                num,
                expected_size
            );
        }
    }

    #[test]
    fn test_left_encoding() {
        let mut buf = [0u8; 9];

        assert_eq!(left_encode(0, &mut buf), &[1, 0]);
        assert_eq!(left_encode(1, &mut buf), &[1, 1]);
        assert_eq!(left_encode(8, &mut buf), &[1, 8]);
        assert_eq!(left_encode(256, &mut buf), &[2, 1, 0]);

        for i in 0..usize::BITS {
            let x: usize = 1 << i;
            let mut want = std::vec![0; 1];
            want.extend(x.to_be_bytes().iter().skip_while(|&&v| v == 0));
            want[0] = (want.len() - 1) as u8;
            assert_eq!(left_encode(x as u64, &mut buf), want, "#{x}");
        }
    }

    #[test]
    fn test_right_encoding() {
        let mut buf = [0u8; 9];

        assert_eq!(right_encode(0, &mut buf), &[0, 1]);
        assert_eq!(right_encode(1, &mut buf), &[1, 1]);
        assert_eq!(right_encode(8, &mut buf), &[8, 1]);
        assert_eq!(right_encode(256, &mut buf), &[1, 0, 2]);

        for i in 0..usize::BITS {
            let x: usize = 1 << i;
            let mut want =
                std::vec::Vec::from_iter(x.to_be_bytes().iter().copied().skip_while(|&v| v == 0));
            want.push(want.len() as u8);
            assert_eq!(right_encode(x as u64, &mut buf), want, "#{x}");
        }
    }
}
