use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::{cmp, io, slice};

use aes_gcm::Aes128Gcm;
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{AeadCipherHelper, CipherKind, LW_BUFFER_SIZE};
use crate::impl_read_utils;
use crate::io::ext::PollUtil;
use crate::proxy::vmess::vmess_stream::{CHUNK_SIZE, MAX_SIZE};

pub struct DecryptedReader {
    // pub for replace buffer
    pub buffer: BytesMut,
    cipher: CipherKind,
    nonce: [u8; 32],
    iv: BytesMut,
    data_length: usize,
    count: u16,
    minimal_data_to_put: usize,
    read_zero: bool,
}

impl DecryptedReader {
    pub fn new(iv: &[u8], security: CipherKind) -> Self {
        let iv = BytesMut::from(iv);
        let buffer = BytesMut::new();
        Self {
            cipher: security,
            buffer,
            nonce: [0u8; 32],
            iv,
            data_length: 0,
            count: 0,
            minimal_data_to_put: 0,
            read_zero: false,
        }
    }

    fn decrypted_data(&mut self) -> bool {
        let aad = [0u8; 0];
        let nonce_len = self.cipher.nonce_len();
        match &mut self.cipher {
            CipherKind::Aes128Gcm(cipher) => cipher.decrypt_inplace_with_slice(
                &self.nonce[..nonce_len],
                &aad,
                &mut self.buffer[..self.data_length],
            ),
            CipherKind::ChaCha20Poly1305(cipher) => cipher.decrypt_inplace_with_slice(
                &self.nonce[..nonce_len],
                &aad,
                &mut self.buffer[..self.data_length],
            ),
        }
    }

    pub fn poll_read_decrypted<R>(
        &mut self,
        ctx: &mut Context<'_>,
        stream: &mut R,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        // 1. read length
        println!(
            "try read aead length, counter:{},buffer_len:{}",
            self.count,
            self.buffer.len()
        );
        let res = self.read_at_least(stream, ctx, 2);
        if res.is_error() {
            if self.read_zero {
                return Poll::Ready(Ok(()));
            }
            return Poll::Pending;
        }

        self.data_length = self.buffer.get_u16() as usize;
        if self.data_length > MAX_SIZE {
            let err = io::Error::new(ErrorKind::InvalidData, "buffer size too large!");
            return Poll::Ready(Err(err));
        }
        self.read_reserve(self.data_length);
        // 2. read data
        let res = self.read_at_least(stream, ctx, self.data_length);
        if res.is_error() {
            if self.read_zero {
                return Poll::Ready(Ok(()));
            }
            return Poll::Pending;
        }
        // 3. construct nonce
        self.nonce[0..2].copy_from_slice(&self.count.to_be_bytes());
        self.nonce[2..12].copy_from_slice(&self.iv[2..12]);

        // 4. decrypted data, includes aead tag
        if !self.decrypted_data() {
            println!("read decrypted failed");
            return Poll::Ready(Err(io::Error::new(ErrorKind::Other, "invalid aead tag")));
        }
        self.count += 1;

        println!(
            "data_length(include aead tag): {},buffer_len:{}",
            self.data_length,
            self.buffer.len()
        );
        self.data_length -= 16; //remove tag
        // 5. put data
        while self.calc_data_to_put(dst) != 0 {
            dst.put_slice(&self.buffer.as_ref()[0..self.minimal_data_to_put]);
            self.data_length -= self.minimal_data_to_put;
            self.buffer.advance(self.minimal_data_to_put);
            println!("buffer len:{}", self.buffer.len());
            println!("put data len:{}", self.minimal_data_to_put);
        }
        self.buffer.advance(16);

        Poll::Ready(Ok(()))
    }

    impl_read_utils!();
}
pub struct EncryptedWriter {
    buffer: BytesMut,
    cipher: CipherKind,
    nonce: [u8; 32],
    pos: usize,
    iv: BytesMut,
    count: u16,
    data_len: usize,
    state: u32, // for state machine generator use
}

impl EncryptedWriter {
    pub fn new(iv: &[u8], security: CipherKind) -> Self {
        let iv = BytesMut::from(iv);
        let buffer = BytesMut::with_capacity(LW_BUFFER_SIZE * 2);
        Self {
            cipher: security,
            buffer,
            nonce: [0u8; 32],
            pos: 0,
            iv,
            count: 0,
            data_len: 0,
            state: 0,
        }
    }

    pub fn poll_write_encrypted<W>(
        &mut self,
        ctx: &mut Context<'_>,
        stream: &mut W,
        data: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        if data.len() == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut minimal_data_to_write =
            cmp::min(CHUNK_SIZE - self.cipher.overhead_len(), data.len());
        let data = &data[..minimal_data_to_write];
        println!("vmess: before encrypted data len:{}", data.len());
        self.encrypted_buffer(data);
        let res = self.write_data(stream, ctx);
        println!("buffer is {:?}", self.buffer);
        self.buffer.clear();
        println!(
            "vmess: write data done,last written len:{}",
            res.get_poll_res()
        );
        let size = res.get_poll_res();

        Poll::Ready(Ok(size))
    }

    fn encrypted_buffer(&mut self, data: &[u8]) {
        self.data_len = data.len();
        println!("raw data len:{}", self.data_len);
        // 1. length is not encrypted
        self.buffer
            .reserve(self.data_len + 2 + self.cipher.tag_len());
        self.buffer
            .put_u16((self.data_len + self.cipher.tag_len()) as u16);
        println!("encrypted buffer len1:{}", self.buffer.len());
        // 2. construct encrypted data buf
        let mbuf = &mut self.buffer.chunk_mut()[..self.data_len + self.cipher.tag_len()];
        let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        self.buffer.put_slice(data);
        println!("encrypted buffer len2:{}", self.buffer.len());

        // 3. construct nonce
        self.nonce[0..2].copy_from_slice(&self.count.to_be_bytes());
        self.nonce[2..12].copy_from_slice(&self.iv[2..12]);
        // 4. encrypted data, reserved aead tag
        let aad = [0u8; 0];
        let nonce_len = self.cipher.nonce_len();
        match &mut self.cipher {
            CipherKind::Aes128Gcm(cipher) => {
                cipher.encrypt_inplace_with_slice(&self.nonce[..nonce_len], &aad, mbuf);
                unsafe { self.buffer.advance_mut(16) };
            }
            CipherKind::ChaCha20Poly1305(cipher) => {
                cipher.encrypt_inplace_with_slice(&self.nonce[..nonce_len], &aad, mbuf);
                unsafe { self.buffer.advance_mut(16) };
            }
        }
        println!("encrypted buffer len3:{}", self.buffer.len());
        self.count += 1;
        self.pos = 0
    }

    #[inline]
    fn write_data<W>(&mut self, w: &mut W, ctx: &mut Context<'_>) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        while self.pos < self.buffer.len() {
            let n = ready!(Pin::new(&mut *w).poll_write(ctx, &self.buffer[self.pos..]))?;
            println!("cur write len:{}", n);
            self.pos += n;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "write zero byte into writer",
                )));
            }
        }
        Poll::Ready(Ok(self.data_len))
    }
}
