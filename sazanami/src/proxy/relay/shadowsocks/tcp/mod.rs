mod aead;
mod stream;

use std::io::Result;
use std::sync::Arc;
use std::task::ready;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;
use sazanami_proto::socks5::Address;
use shadowsocks_crypto::CipherCategory;
use shadowsocks_crypto::CipherKind;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::io::ReadBuf;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream as TcpConnection;
use tracing::trace;

use self::{
    aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter},
    stream::{DecryptedReader as StreamDecryptedReader, EncryptedWriter as StreamEncryptedWriter},
};
use crate::utils::gen_random_bytes;

enum DecryptedReader<T> {
    Aead(AeadDecryptedReader<T>),
    Stream(StreamDecryptedReader<T>),
}

enum EncryptedWriter<T> {
    Aead(AeadEncryptedWriter<T>),
    Stream(StreamEncryptedWriter<T>),
}
/// Steps for initializing a DecryptedReader
#[derive(Debug)]
enum ReadStatus {
    /// Waiting for initializing vector (or nonce for AEAD ciphers)
    ///
    /// (context, Buffer, already_read_bytes, method, key)
    WaitIv(Vec<u8>, usize, CipherKind, Bytes),

    /// Connection is established, DecryptedReader is initialized
    Established,
}

/// A bidirectional stream for communicating with ShadowSocks' server
pub struct SSTcpStream {
    stream: Option<OwnedReadHalf>,
    dec: Option<Arc<Mutex<DecryptedReader<OwnedReadHalf>>>>,
    enc: Arc<Mutex<EncryptedWriter<OwnedWriteHalf>>>,
    read_status: ReadStatus,
}

impl SSTcpStream {
    /// Create a new CryptoStream with the underlying stream connection
    pub async fn connect(
        stream: TcpConnection,
        addr: Address,
        method: CipherKind,
        key: Bytes,
    ) -> Result<SSTcpStream> {
        let prev_len = match method.category() {
            CipherCategory::Stream => method.iv_len(),
            CipherCategory::Aead => method.salt_len(),
            _ => method.iv_len(),
        };

        let iv = match method.category() {
            CipherCategory::Stream => {
                let local_iv = gen_random_bytes(method.iv_len());
                trace!("generated Stream cipher IV {:?}", local_iv);
                local_iv
            }
            CipherCategory::Aead => {
                let local_salt = gen_random_bytes(method.salt_len());
                trace!("generated AEAD cipher salt {:?}", local_salt);

                local_salt
            }
            _ => {
                let local_iv = gen_random_bytes(method.iv_len());
                trace!("generated Stream cipher IV {:?}", local_iv);
                local_iv
            }
        };

        let (r, w) = stream.into_split();

        let enc = match method.category() {
            CipherCategory::Stream => {
                EncryptedWriter::Stream(StreamEncryptedWriter::new(w, method, &key, iv))
            }
            CipherCategory::Aead => {
                EncryptedWriter::Aead(AeadEncryptedWriter::new(w, method, &key, iv))
            }
            _ => EncryptedWriter::Stream(StreamEncryptedWriter::new(w, method, &key, iv)),
        };

        let mut ss_stream = SSTcpStream {
            stream: Some(r),
            dec: None,
            enc: Arc::new(Mutex::new(enc)),
            read_status: ReadStatus::WaitIv(vec![0u8; prev_len], 0usize, method, key),
        };

        let mut addr_buf = BytesMut::with_capacity(addr.serialized_len());
        addr.write_to_buf(&mut addr_buf);
        ss_stream.write_all(&addr_buf).await?;
        Ok(ss_stream)
    }

    fn poll_read_handshake(
        &mut self,
        cx: &mut Context<'_>,
        mut bufx: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let ReadStatus::WaitIv(ref mut buf, ref mut pos, method, ref key) = self.read_status {
            if self.stream.is_none() {
                return Poll::Pending;
            }

            let mut stream = self.stream.take().unwrap();

            let dec = match method.category() {
                CipherCategory::Stream => DecryptedReader::Stream(StreamDecryptedReader::new(
                    stream,
                    method,
                    key,
                    bufx.initialized_mut(),
                )),
                CipherCategory::Aead => DecryptedReader::Aead(AeadDecryptedReader::new(
                    stream,
                    method,
                    key,
                    bufx.initialized_mut(),
                )),
                _ => DecryptedReader::Stream(StreamDecryptedReader::new(
                    stream,
                    method,
                    key,
                    bufx.initialized_mut(),
                )),
            };

            self.dec = Some(Arc::new(Mutex::new(dec)));
        } else {
            return Poll::Ready(Ok(()));
        };

        self.read_status = ReadStatus::Established;
        Poll::Ready(Ok(()))
    }

    fn priv_poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        ready!(this.poll_read_handshake(ctx, buf))?;

        match *this.dec.as_ref().unwrap().lock() {
            DecryptedReader::Aead(ref mut r) => Pin::new(r).poll_read(ctx, buf),
            DecryptedReader::Stream(ref mut r) => Pin::new(r).poll_read(ctx, buf),
        }
    }

    fn priv_poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match *this.enc.lock() {
            EncryptedWriter::Aead(ref mut w) => Pin::new(w).poll_write(ctx, buf),
            EncryptedWriter::Stream(ref mut w) => Pin::new(w).poll_write(ctx, buf),
        }
    }

    fn priv_poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match *this.enc.lock() {
            EncryptedWriter::Aead(ref mut w) => Pin::new(w).poll_flush(ctx),
            EncryptedWriter::Stream(ref mut w) => Pin::new(w).poll_flush(ctx),
        }
    }

    fn priv_poll_close(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match *this.enc.lock() {
            EncryptedWriter::Aead(ref mut w) => Pin::new(w).poll_shutdown(ctx),
            EncryptedWriter::Stream(ref mut w) => Pin::new(w).poll_shutdown(ctx),
        }
    }
}

impl AsyncRead for SSTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.as_mut().priv_poll_read(ctx, buf)
    }
}

impl AsyncWrite for SSTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.priv_poll_write(ctx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.priv_poll_flush(ctx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        self.priv_poll_close(cx)
    }
}
