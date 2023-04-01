//! AEAD packet I/O facilities
//!
//! AEAD protocol is defined in https://shadowsocks.org/en/spec/AEAD.html.
//!
//! ```plain
//! TCP request (before encryption)
//! +------+---------------------+------------------+
//! | ATYP | Destination Address | Destination Port |
//! +------+---------------------+------------------+
//! |  1   |       Variable      |         2        |
//! +------+---------------------+------------------+
//!
//! TCP request (after encryption, *ciphertext*)
//! +--------+--------------+------------------+--------------+---------------+
//! | NONCE  |  *HeaderLen* |   HeaderLen_TAG  |   *Header*   |  Header_TAG   |
//! +--------+--------------+------------------+--------------+---------------+
//! | Fixed  |       2      |       Fixed      |   Variable   |     Fixed     |
//! +--------+--------------+------------------+--------------+---------------+
//!
//! TCP Chunk (before encryption)
//! +----------+
//! |  DATA    |
//! +----------+
//! | Variable |
//! +----------+
//!
//! TCP Chunk (after encryption, *ciphertext*)
//! +--------------+---------------+--------------+------------+
//! |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
//! +--------------+---------------+--------------+------------+
//! |      2       |     Fixed     |   Variable   |   Fixed    |
//! +--------------+---------------+--------------+------------+
//! ```

use std::io::Result;
use std::task::ready;
use std::{
    cmp, io,
    pin::Pin,
    slice,
    task::{Context, Poll},
    u16,
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
// use crate::crypto::{AeadDecryptor, AeadEncryptor, BoxAeadDecryptor, BoxAeadEncryptor, CipherType};
use shadowsocks_crypto::v1::Cipher;
use shadowsocks_crypto::CipherKind;
use tokio::io::ReadBuf;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::trace;

use super::super::BUFFER_SIZE;

/// AEAD packet payload must be smaller than 0x3FFF
const MAX_PACKET_SIZE: usize = 0x3FFF;

#[derive(Debug)]
enum DecryptReadStep {
    Length,
    Data(usize),
}

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader<T> {
    pub conn: T,
    buffer: BytesMut,
    data: BytesMut,
    cipher: Option<Cipher>,
    pos: usize,
    tag_size: usize,
    steps: DecryptReadStep,
    got_final: bool,
    kind: CipherKind,
    key: Vec<u8>,
}

impl<T: AsyncRead + Unpin> DecryptedReader<T> {
    pub fn new(conn: T, t: CipherKind, key: &[u8], nonce: &[u8]) -> DecryptedReader<T> {
        DecryptedReader {
            conn,
            buffer: BytesMut::with_capacity(BUFFER_SIZE),
            data: BytesMut::with_capacity(BUFFER_SIZE),
            cipher: None,
            pos: 0,
            tag_size: t.tag_len(),
            steps: DecryptReadStep::Length,
            got_final: false,
            kind: t,
            key: key.into(),
        }
    }

    fn poll_read_decrypted(
        &mut self,
        ctx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.cipher.is_none() {
            let mut iv_buf = vec![0; self.kind.salt_len()];
            let mut read_buf = ReadBuf::new(&mut iv_buf);
            ready!(Pin::new(&mut self.conn).poll_read(ctx, &mut read_buf))?;
            trace!("Got ahead cipher size {} => {:?}", iv_buf.len(), iv_buf);
            // set the cipher
            self.cipher = Some(Cipher::new(self.kind, &self.key, &iv_buf))
        }

        while self.pos >= self.data.len() {
            // Already received EOF
            if self.got_final {
                return Poll::Ready(Ok(()));
            }

            // Refill buffer
            match self.steps {
                DecryptReadStep::Length => ready!(self.poll_read_decrypted_length(ctx))?,
                DecryptReadStep::Data(len) => ready!(self.poll_read_decrypted_data(ctx, len))?,
            }
        }

        let remaining_len = self.data.len() - self.pos;
        // BUG:
        let dst_inner = dst.initialized_mut();
        let n = cmp::min(dst_inner.len(), remaining_len);
        dst_inner[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;

        dst.set_filled(n);
        Poll::Ready(Ok(()))
    }

    fn poll_read_decrypted_length(&mut self, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let buf_len = 2 + self.tag_size;
        ready!(self.poll_read_exact(ctx, buf_len, true))?;
        if self.got_final {
            return Poll::Ready(Ok(()));
        }

        // Done reading, decrypt it
        let len = {
            self.cipher
                .as_mut()
                .unwrap()
                .decrypt_packet(&mut self.buffer[..]);
            let len_buf = [self.buffer[0], self.buffer[1]];
            BigEndian::read_u16(&len_buf) as usize
        };

        // Clear buffer before overwriting it
        self.buffer.clear();
        self.data.clear();
        self.pos = 0;

        // Next step, read data
        self.steps = DecryptReadStep::Data(len);
        self.buffer.reserve(len + self.tag_size);
        self.data.reserve(len);

        Poll::Ready(Ok(()))
    }

    fn poll_read_decrypted_data(
        &mut self,
        ctx: &mut Context<'_>,
        size: usize,
    ) -> Poll<io::Result<()>> {
        let buf_len = size + self.tag_size;
        ready!(self.poll_read_exact(ctx, buf_len, false))?;

        // Done reading data, decrypt it
        unsafe {
            // It has enough space, I am sure about that
            let mut buffer =
                slice::from_raw_parts_mut(self.data.chunk_mut().as_mut_ptr() as *mut u8, size);
            // let mut bb = self.buffer.to_owned();
            self.cipher
                .as_mut()
                .unwrap()
                .decrypt_packet(&mut self.buffer);
            buffer.put_slice(&self.buffer[..self.buffer.len() - self.tag_size]);

            // Move forward the pointer
            self.data.advance_mut(size);
        }

        // Clear buffer before overwriting it
        self.buffer.clear();

        // Reset read position
        self.pos = 0;

        // Next step, read length
        self.steps = DecryptReadStep::Length;
        self.buffer.reserve(2 + self.tag_size);

        Poll::Ready(Ok(()))
    }

    fn poll_read_exact(
        &mut self,
        ctx: &mut Context<'_>,
        size: usize,
        allow_eof: bool,
    ) -> Poll<io::Result<()>> {
        while self.buffer.len() < size {
            let remaining = size - self.buffer.len();
            unsafe {
                // It has enough space, I am sure about that
                let buffer = slice::from_raw_parts_mut(
                    self.buffer.chunk_mut().as_mut_ptr() as *mut u8,
                    remaining,
                );

                let mut buf = ReadBuf::new(buffer);
                let before = buf.filled().len();
                ready!(Pin::new(&mut self.conn).poll_read(ctx, &mut buf))?;
                let after = buf.filled().len();

                let n = after - before;

                if n == 0 {
                    if self.buffer.is_empty() && allow_eof && !self.got_final {
                        // Read nothing
                        self.got_final = true;
                        return Poll::Ready(Ok(()));
                    } else {
                        use std::io::ErrorKind;
                        return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                    }
                }
                self.buffer.advance_mut(n);
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for DecryptedReader<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        (*self).poll_read_decrypted(cx, buf)
    }
}

enum EncryptWriteStep {
    Nothing,
    Writing(BytesMut, usize),
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter<T> {
    pub conn: T,
    cipher: Cipher,
    tag_size: usize,
    steps: EncryptWriteStep,
    nonce: Option<Bytes>,
}

impl<T: AsyncWrite + Unpin> EncryptedWriter<T> {
    /// Creates a new EncryptedWriter
    pub fn new(conn: T, t: CipherKind, key: &[u8], nonce: Bytes) -> EncryptedWriter<T> {
        EncryptedWriter {
            conn,
            cipher: Cipher::new(t, key, &nonce),
            tag_size: t.tag_len(),
            steps: EncryptWriteStep::Nothing,
            nonce: Some(nonce),
        }
    }

    fn poll_write_encrypted(
        &mut self,
        ctx: &mut Context<'_>,
        mut data: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // Data.Len is a 16-bit big-endian integer indicating the length of Data. It must be smaller than 0x3FFF.
        if data.len() > MAX_PACKET_SIZE {
            data = &mut data[..MAX_PACKET_SIZE];
        }

        ready!(self.poll_write_all_encrypted(ctx, data))?;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_write_all_encrypted(
        &mut self,
        ctx: &mut Context<'_>,
        mut data: &mut [u8],
    ) -> Poll<io::Result<()>> {
        assert!(
            data.len() <= MAX_PACKET_SIZE,
            "buffer size too large, AEAD encryption protocol requires buffer to be smaller than 0x3FFF"
        );

        loop {
            match self.steps {
                EncryptWriteStep::Nothing => {
                    let output_length = self.buffer_size(data);
                    let data_length = data.len() as u16;

                    // Send the first packet with nonce
                    let nonce_length = match self.nonce {
                        Some(ref n) => n.len(),
                        None => 0,
                    };

                    let mut buf = BytesMut::with_capacity(nonce_length + output_length);

                    // Put nonce first
                    if let Some(n) = self.nonce.take() {
                        buf.extend(n);
                    }

                    let mut data_len_buf = vec![0u8; 2 + self.tag_size];
                    BigEndian::write_u16(&mut data_len_buf, data_length);

                    unsafe {
                        let mut b = slice::from_raw_parts_mut(
                            buf.chunk_mut().as_mut_ptr() as *mut u8,
                            output_length,
                        );

                        let output_length_size = 2 + self.tag_size;

                        self.cipher.encrypt_packet(&mut data_len_buf);
                        b[..output_length_size].copy_from_slice(&data_len_buf);

                        // TODO:
                        let mut data = data.to_vec();
                        data.extend_from_slice(&vec![0; self.tag_size]);
                        self.cipher.encrypt_packet(&mut data);
                        b[output_length_size..output_length].copy_from_slice(&data);

                        buf.advance_mut(output_length);
                    }

                    self.steps = EncryptWriteStep::Writing(buf, 0);
                }
                EncryptWriteStep::Writing(ref mut buf, ref mut pos) => {
                    while *pos < buf.len() {
                        let n = ready!(Pin::new(&mut self.conn).poll_write(ctx, &buf[*pos..]))?;
                        if n == 0 {
                            use std::io::ErrorKind;
                            return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                        }
                        *pos += n;
                    }

                    self.steps = EncryptWriteStep::Nothing;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        2 + self.tag_size // len and len_tag
            + data.len() + self.tag_size // data and data_tag
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for EncryptedWriter<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let mut buf = buf.to_owned();
        (*self).poll_write_encrypted(cx, &mut buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.conn).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}
