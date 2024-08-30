use crate::Table;
use core::arch::aarch64::*;
const CHUNK_SIZE: usize = 512;
const STRIP_SIZE: usize = CHUNK_SIZE / 2;

#[target_feature(enable = "neon")]
pub unsafe fn next_match(hash: &mut u64, table: &Table, buf: &[u8], mask: u64) -> Option<usize> {
    for (ic, chunk) in buf.chunks(CHUNK_SIZE).enumerate() {
        if chunk.len() != CHUNK_SIZE {
            return crate::scalar::next_match(hash, table, chunk, mask)
                .map(|off| off + ic * CHUNK_SIZE);
        }
        let mut hx = 0u64;
        for i in 0..64 {
            let b = *chunk.get_unchecked((STRIP_SIZE - 64) + i);
            hx = (hx << 1).wrapping_add(table[b as usize]);
        }
        let mut h = vcombine_u64(vdup_n_u64(*hash), vdup_n_u64(hx));
        for i in 0..STRIP_SIZE {
            let b0 = *chunk.get_unchecked(STRIP_SIZE * 0 + i);
            let b1 = *chunk.get_unchecked(STRIP_SIZE * 1 + i);
            let g = vcombine_u64(
                vdup_n_u64(table[b0 as usize] as u64),
                vdup_n_u64(table[b1 as usize] as u64),
            );
            h = vaddq_u64(vshlq_n_u64(h, 1), g);
            let m = vandq_u64(h, vdupq_n_u64(mask as u64));
            let c = vceqq_u64(m, vdupq_n_u64(0));
            // Instead of vcvtq_u8_u64 and vaddvq_u8, use this manual approach

            // Check if any of the lanes in 'c' are zero
            let z0 = vgetq_lane_u64(c, 0);
            let z1 = vgetq_lane_u64(c, 1);

            if z0 == 0 && z1 == 0 {
                continue;
            }

            if z0 != 0 {
                *hash = vgetq_lane_u64(h, 0);
                return Some(ic * CHUNK_SIZE + i + 1);
            }

            if z1 != 0 {
                let rest = &chunk[i + 1..STRIP_SIZE];
                *hash = vgetq_lane_u64(h, 0);
                if let Some(off) = crate::scalar::next_match(hash, table, rest, mask) {
                    return Some(ic * CHUNK_SIZE + i + 1 + off);
                } else {
                    *hash = vgetq_lane_u64(h, 1);
                    return Some(ic * CHUNK_SIZE + STRIP_SIZE + i + 1);
                }
            }
        }
        *hash = vgetq_lane_u64(h, 0);
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
