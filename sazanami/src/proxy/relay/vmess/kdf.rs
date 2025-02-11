use hmac::Hmac;
use hmac::Mac;
use sha2::Digest;
use sha2::Sha256;

pub const KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY: &[u8; 22] = b"AES Auth ID Encryption";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY: &[u8; 24] = b"AEAD Resp Header Len Key";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV: &[u8; 23] = b"AEAD Resp Header Len IV";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8; 20] = b"AEAD Resp Header Key";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8; 19] = b"AEAD Resp Header IV";
pub const KDF_SALT_CONST_VMESS_AEAD_KDF: &[u8; 14] = b"VMess AEAD KDF";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY: &[u8; 21] = b"VMess Header AEAD Key";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV: &[u8; 23] = b"VMess Header AEAD Nonce";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8; 28] =
    b"VMess Header AEAD Key_Length";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8; 30] =
    b"VMess Header AEAD Nonce_Length";

// VMessHash, RecursiveHash is copied from https://github.com/cfal/shoes/blob/7ff95f530e1f4d2fbd06a2cfeacc50fc293cd739/src/vmess/sha2.rs
// Copyright (c) 2021-2023 Alex Lau <github@alau.ca>

// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

trait VmessHash: std::fmt::Debug {
    fn chain(&self) -> Box<dyn VmessHash>;
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> [u8; 32];
}

#[derive(Debug)]
struct Sha256Hash(Sha256);

impl Sha256Hash {
    fn new() -> Self {
        Self(Sha256::new())
    }
}

impl VmessHash for Sha256Hash {
    fn chain(&self) -> Box<dyn VmessHash> {
        Box::new(Sha256Hash(self.0.clone()))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        self.0.clone().finalize().into()
    }
}

#[derive(Debug)]
struct RecursiveHash {
    inner: Box<dyn VmessHash>,
    outer: Box<dyn VmessHash>,
    in_: [u8; 64],
    out: [u8; 64],
}

impl RecursiveHash {
    fn create(key: &[u8], hash: Box<dyn VmessHash>) -> Self {
        let mut default_outer = [0u8; 64];
        let mut default_inner = [0u8; 64];

        // for hmac, we would normally have to get a derived key
        // by hashing the key when it's longer than 64 bytes, but
        // that doesn't happen for vmess's usecase.
        assert!(key.len() <= 64);

        default_outer[0..key.len()].copy_from_slice(&key);
        default_inner[0..key.len()].copy_from_slice(&key);

        for b in default_outer.iter_mut() {
            *b ^= 0x5c;
        }
        for b in default_inner.iter_mut() {
            *b ^= 0x36;
        }

        let mut inner = hash.chain();
        let outer = hash;
        inner.update(&default_inner);
        Self {
            inner,
            outer,
            in_: default_inner,
            out: default_outer,
        }
    }
}

impl VmessHash for RecursiveHash {
    fn chain(&self) -> Box<dyn VmessHash> {
        let new_inner = self.inner.chain();
        let new_outer = self.outer.chain();

        let mut new_in = [0u8; 64];
        let mut new_out = [0u8; 64];
        new_in.copy_from_slice(&self.in_);
        new_out.copy_from_slice(&self.out);

        Box::new(RecursiveHash {
            inner: new_inner,
            outer: new_outer,
            in_: new_in,
            out: new_out,
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        let inner_result: [u8; 32] = self.inner.finalize().into();
        self.outer.update(&self.out);
        self.outer.update(&inner_result);
        self.outer.finalize().into()
    }
}

pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut current = Box::new(RecursiveHash::create(
        KDF_SALT_CONST_VMESS_AEAD_KDF,
        Box::new(Sha256Hash::new()),
    ));
    for path_item in path.into_iter() {
        current = Box::new(RecursiveHash::create(path_item, current))
    }
    current.update(key);
    current.finalize()
}

#[cfg(test)]
mod vmess_kdf_test {
    use std::num::ParseIntError;

    use hex_literal::hex;
    use sha2::Sha256;

    use super::*;

    fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }

    #[test]
    fn test_vmess_kdf1() {
        use super::kdf;
        let id = b"1234567890123456";
        let mut h = kdf(
            id,
            &[
                KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
                KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
            ],
        );
        let expected =
            decode_hex("2745934f3b987d077b4082ec0f76060f33d7f4d89dd172f434c275bf91b1360b").unwrap();
        assert_eq!(h.to_vec(), expected);
    }
}
