#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use crate::simd::avx2;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use crate::simd::avx2;
#[cfg(any(target_arch = "aarch64"))]
pub use crate::simd::neon;
