//! Stream protocol implementation

use std::io::Result;
use std::task::ready;
use std::{
    cmp, io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, Bytes, BytesMut};
use shadowsocks_crypto::v1::Cipher;
use shadowsocks_crypto::CipherKind;
use tokio::io::ReadBuf;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::trace;

use super::super::BUFFER_SIZE;

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader<T> {
    pub conn: T,
    buffer: BytesMut,
    cipher: Option<Cipher>,
    pos: usize,
    got_final: bool,
    incoming_buffer: Vec<u8>,
    key: Vec<u8>,
    kind: CipherKind,
}

impl<T: AsyncRead + Unpin> DecryptedReader<T> {
    // TODO: iv is from handshake packet, remove this parameter
    pub fn new(conn: T, t: CipherKind, key: &[u8], iv: &[u8]) -> DecryptedReader<T> {
        DecryptedReader {
            conn,
            buffer: BytesMut::with_capacity(BUFFER_SIZE),
            cipher: None,
            pos: 0,
            got_final: false,
            incoming_buffer: vec![0u8; BUFFER_SIZE],
            key: key.into(),
            kind: t,
        }
    }

    fn poll_read_decrypted(
        &mut self,
        ctx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Create cipher from handshake packet
        if self.cipher.is_none() {
            // this must be a stream kind, so use iv_len()
            let mut iv_buf = vec![0; self.kind.iv_len()];
            let mut read_buf = ReadBuf::new(&mut iv_buf);

            ready!(Pin::new(&mut self.conn).poll_read(ctx, &mut read_buf))?;

            trace!("Got stream cipher size {} => {:?}", iv_buf.len(), iv_buf);
            // set the cipher
            self.cipher = Some(Cipher::new(self.kind, &self.key, &iv_buf))
        }

        while self.pos >= self.buffer.len() {
            if self.got_final {
                return Poll::Ready(Ok(()));
            }

            let mut buf = ReadBuf::new(&mut self.incoming_buffer);

            let before = buf.filled().len();
            ready!(Pin::new(&mut self.conn).poll_read(ctx, &mut buf))?;
            let after = buf.filled().len();
            let n = after - before;

            // Reset pointers
            self.buffer.clear();
            self.pos = 0;

            if n == 0 {
                self.buffer.reserve(self.buffer_size(&[]));
                self.cipher
                    .as_mut()
                    .unwrap()
                    .decrypt_packet(&mut self.buffer);
                self.got_final = true;
            } else {
                let mut data = &mut self.incoming_buffer[..n];
                // Ensure we have enough space
                // FIXME:
                let buffer_len = n;
                self.buffer.reserve(buffer_len);
                // let mut packet = data.to_owned();
                self.cipher.as_mut().unwrap().decrypt_packet(&mut data);

                self.buffer.put_slice(data)
            }
        }

        let remaining_len = self.buffer.len() - self.pos;
        // BUG:
        let dst_inner = dst.initialized_mut();
        let n = cmp::min(dst_inner.len(), remaining_len);
        dst_inner[..n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
        self.pos += n;

        dst.set_filled(n);
        Poll::Ready(Ok(()))
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        // FIXME:
        data.len() + 128
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

#[derive(Debug)]
enum EncryptWriteStep {
    Nothing,
    Writing(BytesMut, usize),
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter<T> {
    pub conn: T,
    cipher: Cipher,
    steps: EncryptWriteStep,
    iv: Option<Bytes>,
}

impl<T: AsyncWrite + Unpin> EncryptedWriter<T> {
    /// Creates a new EncryptedWriter
    pub fn new(conn: T, t: CipherKind, key: &[u8], iv: Bytes) -> EncryptedWriter<T> {
        EncryptedWriter {
            conn,
            cipher: Cipher::new(t, key, &iv),
            steps: EncryptWriteStep::Nothing,
            iv: Some(iv),
        }
    }

    fn poll_write_encrypted(
        &mut self,
        ctx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_write_all_encrypted(ctx, data))?;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_write_all_encrypted(
        &mut self,
        ctx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<()>> {
        loop {
            match self.steps {
                EncryptWriteStep::Nothing => {
                    // Send the first packet with iv
                    let iv_length = match self.iv {
                        Some(ref i) => i.len(),
                        None => 0,
                    };

                    let mut buf = BytesMut::with_capacity(iv_length + data.len());

                    // Put iv first
                    if let Some(i) = self.iv.take() {
                        buf.extend(i);
                    }

                    let mut bb = data.to_owned();
                    self.cipher.encrypt_packet(&mut bb);
                    buf.extend(bb);

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
}

impl<T: AsyncWrite + Unpin> AsyncWrite for EncryptedWriter<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        (*self).poll_write_encrypted(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.conn).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}
