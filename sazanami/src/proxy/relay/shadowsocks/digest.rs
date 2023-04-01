use std::mem;

use bytes::{BufMut, Bytes, BytesMut};
use digest::OutputSizeUser;
use md5::Md5;
use sha1::Sha1;

/// Digest trait
pub trait Digest: Send {
    /// Update data
    fn update(&mut self, data: &[u8]);

    /// Generates digest
    fn digest_reset<B: BufMut>(&mut self, buf: &mut B);

    /// Length of digest
    fn digest_len(&self) -> usize;
}

/// Type of defined digests
#[derive(Clone, Copy)]
pub enum DigestType {
    Md5,
    Sha1,
    Sha,
}

/// Create digest with type
pub fn with_type(t: DigestType) -> DigestVariant {
    match t {
        DigestType::Md5 => DigestVariant::Md5(Md5::default()),
        DigestType::Sha1 | DigestType::Sha => DigestVariant::Sha1(Sha1::default()),
    }
}

/// Variant of supported digest
pub enum DigestVariant {
    Md5(Md5),
    Sha1(Sha1),
}

impl Digest for DigestVariant {
    fn update(&mut self, data: &[u8]) {
        use md5::Digest;

        match *self {
            DigestVariant::Md5(ref mut d) => d.update(data),
            DigestVariant::Sha1(ref mut d) => d.update(data),
        }
    }

    fn digest_reset<B: BufMut>(&mut self, buf: &mut B) {
        use digest::Digest;
        match self {
            DigestVariant::Md5(d) => buf.put(&*d.finalize_reset()),
            DigestVariant::Sha1(d) => buf.put(&*d.finalize_reset()),
        }
    }

    fn digest_len(&self) -> usize {
        match *self {
            DigestVariant::Md5(_) => <Md5 as OutputSizeUser>::output_size(),
            DigestVariant::Sha1(_) => <Sha1 as OutputSizeUser>::output_size(),
        }
    }
}

pub fn bytes_to_key(key: &[u8], key_len: usize, iv_len: usize) -> Bytes {
    if iv_len + key_len == 0 {
        return Bytes::new();
    }

    let mut digest = with_type(DigestType::Md5);

    let total_loop = (key_len + iv_len + digest.digest_len() - 1) / digest.digest_len();
    let m_length = digest.digest_len() + key.len();

    let mut result = BytesMut::with_capacity(total_loop * digest.digest_len());
    let mut m = BytesMut::with_capacity(key.len());

    for _ in 0..total_loop {
        let mut vkey = mem::replace(&mut m, BytesMut::with_capacity(m_length));
        vkey.put(key);

        digest.update(&vkey);
        digest.digest_reset(&mut m);

        result.put_slice(&m);
    }

    result.truncate(key_len);
    result.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_key() {
        let key = &[
            48, 35, 244, 71, 88, 77, 184, 43, 254, 41, 201, 179, 213, 250, 154, 162,
        ];
        let rt = bytes_to_key(key, 16, 16);
        assert_eq!(
            rt,
            Bytes::from_static(b"\xc6\tn\x0e\xfc\x14&\xde\x0e\xf7y\x1eo\xd4\xa0\xf1")
        );
    }
}
