use crate::Table;

#[inline]
pub(crate) fn next_match(hash: &mut u64, table: &Table, buf: &[u8], mask: u64) -> Option<usize> {
    for (i, b) in buf.iter().enumerate() {
        *hash = (*hash << 1).wrapping_add(table[*b as usize]);

        if *hash & mask == 0 {
            return Some(i + 1);
        }
    }

    None
}

#[inline]
pub(crate) fn next_match_1x_impr(
    hash: &mut u64,
    table: &Table,
    buf: &[u8],
    mask: u64,
) -> Option<usize> {
    let mut h = *hash;
    for (i, b) in buf.iter().enumerate() {
        h = (h << 1).wrapping_add(table[*b as usize]);

        if h & mask == 0 {
            *hash = h;
            return Some(i + 1);
        }
    }
    *hash = h;

    None
}

#[inline]
pub(crate) fn next_match_2x_iter(
    hash: &mut u64,
    table: &Table,
    buf: &[u8],
    mask: u64,
) -> Option<usize> {
    let chunks = buf.chunks_exact(2);
    let remainder = chunks.remainder();

    let mut h = *hash;

    for (i, barr) in chunks.enumerate() {
        let b0 = barr[0];
        let t0 = table[b0 as usize];

        let b1 = barr[1];
        let t1 = table[b1 as usize];

        let hash0 = (h << 1).wrapping_add(t0);
        let hash1 = (h << 2).wrapping_add(t0 << 1).wrapping_add(t1);

        if hash0 & mask == 0 {
            *hash = hash0;
            return Some((i << 1) + 1);
        }

        if hash1 & mask == 0 {
            *hash = hash1;
            return Some((i << 1) + 2);
        }

        h = hash1;
    }

    if !remainder.is_empty() {
        let b = remainder[0];
        let t = table[b as usize];
        h = (h << 1).wrapping_add(t);

        if h & mask == 0 {
            *hash = h;
            return Some(buf.len());
        }
    }

    *hash = h;

    None
}

#[inline]
pub(crate) fn next_match_2x_idx(
    hash: &mut u64,
    table: &Table,
    buf: &[u8],
    mask: u64,
) -> Option<usize> {
    let len = buf.len();
    let end2 = len - (len & 1);

    let mut i = 0;
    let mut h = *hash;

    while i < end2 {
        let b0 = buf[i];
        let t0 = table[b0 as usize];

        let b1 = buf[i + 1];
        let t1 = table[b1 as usize];

        let hash0 = (h << 1).wrapping_add(t0);
        let hash1 = (h << 2).wrapping_add(t0 << 1).wrapping_add(t1);

        if hash0 & mask == 0 {
            *hash = hash0;
            return Some(i + 1);
        }

        if hash1 & mask == 0 {
            *hash = hash1;
            return Some(i + 2);
        }

        h = hash1;
        i += 2;
    }

    if end2 != len {
        let b = buf[end2];
        let t = table[b as usize];
        h = (h << 1).wrapping_add(t);

        if h & mask == 0 {
            *hash = h;
            return Some(len);
        }
    }

    *hash = h;

    None
}

#[inline]
pub(crate) fn next_match_4x_idx(
    hash: &mut u64,
    table: &Table,
    buf: &[u8],
    mask: u64,
) -> Option<usize> {
    let len = buf.len();
    let mut end4 = len - (len & 3);

    let mut i = 0;
    let mut h = *hash;

    while i < end4 {
        let b0 = buf[i];
        let t0 = table[b0 as usize];

        let b1 = buf[i + 1];
        let t1 = table[b1 as usize];

        let b2 = buf[i + 2];
        let t2 = table[b2 as usize];

        let b3 = buf[i + 3];
        let t3 = table[b3 as usize];

        let hash0 = (h << 1).wrapping_add(t0);
        let hash1 = (h << 2).wrapping_add(t0 << 1).wrapping_add(t1);
        let hash2 = (hash0 << 2).wrapping_add(t1 << 1).wrapping_add(t2);
        let hash3 = (hash1 << 2).wrapping_add(t2 << 1).wrapping_add(t3);

        if hash0 & mask == 0 {
            *hash = hash0;
            return Some(i + 1);
        }

        if hash1 & mask == 0 {
            *hash = hash1;
            return Some(i + 2);
        }

        if hash2 & mask == 0 {
            *hash = hash2;
            return Some(i + 3);
        }

        if hash3 & mask == 0 {
            *hash = hash3;
            return Some(i + 4);
        }

        h = hash3;
        i += 4;
    }

    while end4 < len {
        let b = buf[end4];
        let t = table[b as usize];
        h = (h << 1).wrapping_add(t);

        if h & mask == 0 {
            *hash = h;
            return Some(end4 + 1);
        }

        end4 += 1;
    }

    *hash = h;

    None
}

#[cfg(test)]
mod tests {
    use super::next_match;
    use super::next_match_1x_impr;
    use super::next_match_2x_idx;
    use super::next_match_2x_iter;
    use super::next_match_4x_idx;
    use crate::DEFAULT_TABLE;

    quickcheck::quickcheck! {
        fn check_1x_idx_against_scalar(seed: u64, mask: u64) -> bool {
            let mut bytes = [0u8; 10240];
            let mut rng: rand::rngs::StdRng = rand::SeedableRng::seed_from_u64(seed);
            rand::RngCore::fill_bytes(&mut rng, &mut bytes);

            let mut hash1 = 0;
            let mut hash2 = 0;

            let mut offset = 0;
            while offset < 10240 {
                let result_scalar = next_match(&mut hash1, &DEFAULT_TABLE, &bytes[offset..], mask);
                let result_accelx = next_match_1x_impr(&mut hash2, &DEFAULT_TABLE, &bytes[offset..], mask);

                match (result_scalar, result_accelx) {
                    (Some(a), Some(b)) => {
                        if a != b {
                            return false;
                        }
                        offset += a;
                    }
                    (None, None) => {
                        return true;
                    }
                    _ => {
                        return false;
                    }
                }
            }

            true
        }

        fn check_2x_iter_against_scalar(seed: u64, mask: u64) -> bool {
            let mut bytes = [0u8; 10240];
            let mut rng: rand::rngs::StdRng = rand::SeedableRng::seed_from_u64(seed);
            rand::RngCore::fill_bytes(&mut rng, &mut bytes);

            let mut hash1 = 0;
            let mut hash2 = 0;

            let mut offset = 0;
            while offset < 10240 {
                let result_scalar = next_match(&mut hash1, &DEFAULT_TABLE, &bytes[offset..], mask);
                let result_accelx = next_match_2x_iter(&mut hash2, &DEFAULT_TABLE, &bytes[offset..], mask);

                match (result_scalar, result_accelx) {
                    (Some(a), Some(b)) => {
                        if a != b {
                            return false;
                        }
                        offset += a;
                    }
                    (None, None) => {
                        return true;
                    }
                    _ => {
                        return false;
                    }
                }
            }

            true
        }


        fn check_2x_idx_against_scalar(seed: u64, mask: u64) -> bool {
            let mut bytes = [0u8; 10240];
            let mut rng: rand::rngs::StdRng = rand::SeedableRng::seed_from_u64(seed);
            rand::RngCore::fill_bytes(&mut rng, &mut bytes);

            let mut hash1 = 0;
            let mut hash2 = 0;

            let mut offset = 0;
            while offset < 10240 {
                let result_scalar = next_match(&mut hash1, &DEFAULT_TABLE, &bytes[offset..], mask);
                let result_accelx = next_match_2x_idx(&mut hash2, &DEFAULT_TABLE, &bytes[offset..], mask);

                match (result_scalar, result_accelx) {
                    (Some(a), Some(b)) => {
                        if a != b {
                            return false;
                        }
                        offset += a;
                    }
                    (None, None) => {
                        return true;
                    }
                    _ => {
                        return false;
                    }
                }
            }

            true
        }

        fn check_4x_idx_against_scalar(seed: u64, mask: u64) -> bool {
            let mut bytes = [0u8; 10240];
            let mut rng: rand::rngs::StdRng = rand::SeedableRng::seed_from_u64(seed);
            rand::RngCore::fill_bytes(&mut rng, &mut bytes);

            let mut hash1 = 0;
            let mut hash2 = 0;

            let mut offset = 0;
            while offset < 10240 {
                let result_scalar = next_match(&mut hash1, &DEFAULT_TABLE, &bytes[offset..], mask);
                let result_accelx = next_match_4x_idx(&mut hash2, &DEFAULT_TABLE, &bytes[offset..], mask);

                match (result_scalar, result_accelx) {
                    (Some(a), Some(b)) => {
                        if a != b {
                            return false;
                        }
                        offset += a;
                    }
                    (None, None) => {
                        return true;
                    }
                    _ => {
                        return false;
                    }
                }
            }

            true
        }
    }
}

#[cfg(feature = "bench")]
#[bench]
fn throughput(b: &mut test::Bencher) {
    crate::bench::throughput(b, |hash, buf, mask| {
        next_match(hash, &crate::DEFAULT_TABLE, buf, mask)
    })
}

#[cfg(feature = "bench")]
#[bench]
fn throughput_1x_impr(b: &mut test::Bencher) {
    crate::bench::throughput(b, |hash, buf, mask| {
        next_match_1x_impr(hash, &crate::DEFAULT_TABLE, buf, mask)
    })
}

#[cfg(feature = "bench")]
#[bench]
fn throughput_2x_idx(b: &mut test::Bencher) {
    crate::bench::throughput(b, |hash, buf, mask| {
        next_match_2x_idx(hash, &crate::DEFAULT_TABLE, buf, mask)
    })
}

#[cfg(feature = "bench")]
#[bench]
fn throughput_2x_iter(b: &mut test::Bencher) {
    crate::bench::throughput(b, |hash, buf, mask| {
        next_match_2x_iter(hash, &crate::DEFAULT_TABLE, buf, mask)
    })
}

#[cfg(feature = "bench")]
#[bench]
fn throughput_4x_idx(b: &mut test::Bencher) {
    crate::bench::throughput(b, |hash, buf, mask| {
        next_match_4x_idx(hash, &crate::DEFAULT_TABLE, buf, mask)
    })
}
