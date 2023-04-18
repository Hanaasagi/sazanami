use std::hash::Hasher;

use bytes::Bytes;
use bytes::BytesMut;
use rand;
use rand::RngCore;

pub fn gen_random_bytes(len: usize) -> Bytes {
    let mut iv = BytesMut::with_capacity(len);
    unsafe {
        iv.set_len(len);
    }

    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut iv);
    iv.freeze()
}

pub fn fill_random_bytes(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    let mut rng = rand::thread_rng();
    loop {
        rand::Rng::fill(&mut rng, buf);
        let all_zeros = buf.iter().all(|&x| x == 0);
        if !all_zeros {
            return;
        }
    }
}

pub fn epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[macro_export]
macro_rules! md5 {
    ($($x:expr),*) => {{
        use md5::{Md5, Digest};
        let mut digest = Md5::new();
        $(digest.update($x);)*
        digest.finalize().into()
    }}
}

#[macro_export]
macro_rules! sha256 {
    ($($x:expr),*) => {{
        use sha2::{Sha256, Digest};
        let mut digest = Sha256::new();
        $(digest.update($x);)*
        digest.finalize().into()
    }}
}

pub struct Fnv1aHasher(u32);

impl Default for Fnv1aHasher {
    fn default() -> Fnv1aHasher {
        Fnv1aHasher(0x811c9dc5u32)
    }
}

impl Hasher for Fnv1aHasher {
    fn finish(&self) -> u64 {
        self.0 as u64
    }

    fn write(&mut self, bytes: &[u8]) {
        let Fnv1aHasher(mut hash) = *self;

        for byte in bytes.iter() {
            hash ^= *byte as u32;
            hash = hash.wrapping_mul(0x01000193);
        }

        *self = Fnv1aHasher(hash);
    }
}

#[macro_export]
macro_rules! fnv1a {
    ($($x:expr),*) => {{
        use crate::utils::Fnv1aHasher;
        let mut digest = Fnv1aHasher::default();
        $(digest.write($x);)*
        digest.finish()
    }}
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_gen_random_bytes() {
        let b1 = gen_random_bytes(16);
        let b2 = gen_random_bytes(16);

        assert_ne!(b1, b2);
    }

    #[test]
    fn test_fill_random_bytes() {
        let mut b1 = [0u8; 16];
        fill_random_bytes(&mut b1);
        let mut b2 = [0u8; 16];
        fill_random_bytes(&mut b2);

        assert_ne!(b1, b2);

        assert!(!b1.iter().all(|&x| x == 0));
        assert!(!b2.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_sha256() {
        let res: [u8; 32] = sha256!("hello world");
        assert_eq!(
            res,
            [
                185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196, 132,
                239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233
            ],
        )
    }

    #[test]
    fn test_md5() {
        let res: [u8; 16] = md5!("admin");
        assert_eq!(
            res,
            [
                33, 35, 47, 41, 122, 87, 165, 167, 67, 137, 74, 14, 74, 128, 31, 195
            ],
        )
    }

    #[test]
    fn test_fnv1a() {
        let res = fnv1a!(&[1, 2, 4, 5, 6]) as u32;
        assert_eq!(res, 59409728,)
    }
}
