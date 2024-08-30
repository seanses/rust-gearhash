use crate::Table;
use core::arch::aarch64::*;
const CHUNK_SIZE: usize = 1024;
const STRIP_SIZE: usize = CHUNK_SIZE / 4;

#[target_feature(enable = "neon")]
pub unsafe fn next_match(hash: &mut u64, table: &Table, buf: &[u8], mask: u64) -> Option<usize> {
    for (ic, chunk) in buf.chunks(CHUNK_SIZE).enumerate() {
        if chunk.len() != CHUNK_SIZE {
            return crate::scalar::next_match(hash, table, chunk, mask)
                .map(|off| off + ic * CHUNK_SIZE);
        }

        let mut h01 = vdupq_n_u64(0);
        let mut h23 = vdupq_n_u64(0);

        for i in 0..64 {
            let b1 = *chunk.get_unchecked((STRIP_SIZE * 1 - 64) + i);
            let b2 = *chunk.get_unchecked((STRIP_SIZE * 2 - 64) + i);
            let b3 = *chunk.get_unchecked((STRIP_SIZE * 3 - 64) + i);

            let g01 = vcombine_u64(vdup_n_u64(0), vdup_n_u64(table[b1 as usize] as u64));
            let g23 = vcombine_u64(
                vdup_n_u64(table[b2 as usize] as u64),
                vdup_n_u64(table[b3 as usize] as u64),
            );
            h01 = vaddq_u64(vshlq_n_u64(h01, 1), g01);
            h23 = vaddq_u64(vshlq_n_u64(h23, 1), g23);
        }
        h01 = vsetq_lane_u64::<0>(*hash, h01);
        let mut pre_off = usize::max_value();
        let mut pre_hash = 0u64;

        let msk = vdupq_n_u64(mask as u64);
        for i in 0..STRIP_SIZE {
            let b0 = *chunk.get_unchecked(STRIP_SIZE * 0 + i);
            let b1 = *chunk.get_unchecked(STRIP_SIZE * 1 + i);
            let b2 = *chunk.get_unchecked(STRIP_SIZE * 2 + i);
            let b3 = *chunk.get_unchecked(STRIP_SIZE * 3 + i);
            let g01 = vcombine_u64(
                vdup_n_u64(table[b0 as usize] as u64),
                vdup_n_u64(table[b1 as usize] as u64),
            );
            let g23 = vcombine_u64(
                vdup_n_u64(table[b2 as usize] as u64),
                vdup_n_u64(table[b3 as usize] as u64),
            );
            h01 = vaddq_u64(vshlq_n_u64(h01, 1), g01);
            h23 = vaddq_u64(vshlq_n_u64(h23, 1), g23);
            let m01 = vandq_u64(h01, msk);
            let m23 = vandq_u64(h23, msk);
            let c01 = vceqq_u64(m01, vdupq_n_u64(0));
            let c23 = vceqq_u64(m23, vdupq_n_u64(0));
            // Instead of vcvtq_u8_u64 and vaddvq_u8, use this manual approach

            // Check if any of the lanes in 'c' are zero
            let z0 = vgetq_lane_u64(c01, 0);
            let z1 = vgetq_lane_u64(c01, 1);
            let z2 = vgetq_lane_u64(c23, 0);
            let z3 = vgetq_lane_u64(c23, 1);

            if z0 == 0 && z1 == 0 && z2 == 0 && z3 == 0 {
                continue;
            }

            if z0 != 0 {
                *hash = vgetq_lane_u64(h01, 0);
                return Some(ic * CHUNK_SIZE + i + 1);
            }

            if z1 != 0 {
                let rest = &chunk[i + 1..STRIP_SIZE];
                *hash = vgetq_lane_u64(h01, 0);
                if let Some(off) = crate::scalar::next_match(hash, table, rest, mask) {
                    return Some(ic * CHUNK_SIZE + i + 1 + off);
                } else {
                    *hash = vgetq_lane_u64(h01, 1);
                    return Some(ic * CHUNK_SIZE + STRIP_SIZE + i + 1);
                }
            }

            if z2 != 0 {
                let off = STRIP_SIZE * 2 + i;
                if off < pre_off {
                    pre_off = off;
                    pre_hash = vgetq_lane_u64(h23, 0);
                }
            }

            if z3 != 0 {
                let off = STRIP_SIZE * 3 + i;
                if off < pre_off {
                    pre_off = off;
                    pre_hash = vgetq_lane_u64(h23, 1);
                }
            }
        }

        if pre_off != usize::max_value() {
            *hash = pre_hash;
            return Some(ic * CHUNK_SIZE + pre_off + 1);
        }
        *hash = vgetq_lane_u64(h01, 0);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::next_match;
    use crate::DEFAULT_TABLE;

    quickcheck::quickcheck! {
        fn check_against_scalar(seed: u64, mask: u64) -> bool {
            let mut bytes = [0u8; 10240];
            let mut rng: rand::rngs::StdRng = rand::SeedableRng::seed_from_u64(seed);
            rand::RngCore::fill_bytes(&mut rng, &mut bytes);

            let mut hash1 = 0;
            let mut hash2 = 0;

            let mut offset = 0;
            while offset < 10240 {
                let result_scalar = crate::scalar::next_match(&mut hash1, &DEFAULT_TABLE, &bytes[offset..], mask);
                let result_accel = unsafe { next_match(&mut hash2, &DEFAULT_TABLE, &bytes[offset..], mask) };

                match (result_scalar, result_accel) {
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
    if std::arch::is_aarch64_feature_detected!("neon") {
        crate::bench::throughput(b, |hash, buf, mask| unsafe {
            next_match(hash, &crate::DEFAULT_TABLE, buf, mask)
        })
    }
}
