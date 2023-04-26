use std::hash::Hasher;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::ready;
use std::task::{Context, Poll};

use aes_gcm::Aes128Gcm;
use bytes::{BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use rand::random;
use sazanami_proto::socks5::Address;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tracing::debug;

use super::aead::{DecryptedReader, EncryptedWriter};
use super::aead_header::{seal_vmess_aead_header, VmessHeaderReader};
use super::AeadCipherHelper;
use super::CipherKind;
use super::VmessOption;
use crate::fnv1a;
use crate::io::ext::PollUtil;
use crate::md5;
use crate::sha256;
use crate::utils::fill_random_bytes;

pub const MAX_SIZE: usize = 17 * 1024;
pub const CHUNK_SIZE: usize = 1 << 14;
pub const VERSION: u8 = 1;
pub const OPT_CHUNK_STREAM: u8 = 1;
pub const COMMAND_UDP: u8 = 0x02;
pub const COMMAND_TCP: u8 = 0x01;
pub const AES_128_GCM_SECURITY_NUM: u8 = 0x03;
pub const CHACHA20POLY1305_SECURITY_NUM: u8 = 0x04;
#[allow(dead_code)]
pub const NONE_SECURITY_NUM: u8 = 0x05;

pub const ADDR_TYPE_IPV4: u8 = 1;
pub const ADDR_TYPE_DOMAIN_NAME: u8 = 3;
pub const ADDR_TYPE_IPV6: u8 = 4;

pub fn write_addr_to_buf<B: BufMut>(addr: &Address, buf: &mut B) {
    match addr {
        Address::SocketAddress(SocketAddr::V4(addr)) => {
            buf.put_u16(addr.port());
            buf.put_u8(0x01);
            buf.put_slice(&addr.ip().octets());
        }
        Address::SocketAddress(SocketAddr::V6(addr)) => {
            buf.put_u16(addr.port());
            buf.put_u8(0x03);
            for seg in &addr.ip().segments() {
                buf.put_u16(*seg);
            }
        }
        Address::DomainNameAddress(domain_name, port) => {
            buf.put_u16(*port);
            buf.put_u8(0x02);
            buf.put_u8(domain_name.len() as u8);
            buf.put_slice(domain_name.as_bytes());
        }
    }
}

pub struct VmessStream<T> {
    stream: T,
    option: VmessOption,
    reader: DecryptedReader,
    writer: EncryptedWriter,
    header_reader: Box<VmessHeaderReader>,
    header_buffer: BytesMut,
    header_pos: usize,

    // header maybe re-created
    req_iv: [u8; 16],
    req_key: [u8; 16],
    respv: u8,
}

impl<T> VmessStream<T> {
    pub fn new(option: VmessOption, stream: T) -> VmessStream<T> {
        let mut salt = [0u8; 64];
        fill_random_bytes(&mut salt);
        let respv = salt[32];

        let key: [u8; 32] = sha256!(&salt[16..32]);
        let iv: [u8; 32] = sha256!(&salt[0..16]);

        salt[32..48].copy_from_slice(&key[..16]);
        salt[48..64].copy_from_slice(&iv[..16]);

        let req_iv = &salt[0..16];
        let req_key = &salt[16..32];
        let resp_key = &salt[32..48];
        let resp_iv = &salt[48..];

        debug!("req body key:{:02X?}", &req_key);
        debug!("resp body key:{:02X?}", &resp_key);

        let reader = Self::create_reader(option.security_num, resp_key, resp_iv);
        let writer = Self::create_writer(option.security_num, req_key, req_iv);

        Self {
            stream,
            option: option.clone(),
            reader,
            writer,
            req_iv: req_iv.try_into().expect("slice with incorrect length"),
            req_key: req_key.try_into().expect("slice with incorrect length"),
            respv,
            header_reader: Box::new(VmessHeaderReader::new(
                &resp_key[..16],
                &resp_iv[..16],
                respv,
            )),
            header_buffer: Self::construct_header(&option, req_iv, req_key, respv),
            header_pos: 0,
        }
    }

    fn create_writer(security_num: u8, key: &[u8], iv: &[u8]) -> EncryptedWriter {
        let cipher = match security_num {
            AES_128_GCM_SECURITY_NUM => CipherKind::Aes128Gcm(Aes128Gcm::new_with_slice(key)),
            CHACHA20POLY1305_SECURITY_NUM => {
                let mut new_key = bytes::BytesMut::with_capacity(32);
                new_key[0..16].copy_from_slice(&md5!(key) as &[u8; 16]);
                new_key[16..32].copy_from_slice(&md5!(&key[16..]) as &[u8; 16]);
                CipherKind::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&new_key))
            }
            _ => {
                unimplemented!();
            }
        };
        EncryptedWriter::new(iv, cipher)
    }

    fn create_reader(security_num: u8, key: &[u8], iv: &[u8]) -> DecryptedReader {
        let cipher = match security_num {
            AES_128_GCM_SECURITY_NUM => CipherKind::Aes128Gcm(Aes128Gcm::new_with_slice(key)),
            CHACHA20POLY1305_SECURITY_NUM => {
                let mut new_key = bytes::BytesMut::with_capacity(32);
                new_key[0..16].copy_from_slice(&md5!(key) as &[u8; 16]);
                new_key[16..32].copy_from_slice(&md5!(&key[16..]) as &[u8; 16]);
                CipherKind::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&new_key))
            }
            _ => {
                unimplemented!();
            }
        };
        DecryptedReader::new(iv, cipher)
    }

    fn construct_header(
        option: &VmessOption,
        req_iv: &[u8],
        req_key: &[u8],
        respv: u8,
    ) -> BytesMut {
        let mut buf = BytesMut::new();

        buf.put_u8(VERSION);
        buf.put(req_iv.as_ref());
        buf.put(req_key.as_ref());
        debug!("req body key:{:02X?}", req_key);
        buf.put_u8(respv);
        buf.put_u8(OPT_CHUNK_STREAM);

        let x = random::<u8>() % 16;
        buf.put_u8((x << 4) | option.security_num);
        buf.put_u8(0);
        buf.put_u8(if option.is_udp {
            debug!("vmess command udp detected");
            COMMAND_UDP
        } else {
            COMMAND_TCP
        });
        write_addr_to_buf(&option.addr, &mut buf);
        if x > 0 {
            let mut padding = [0u8; 16];
            fill_random_bytes(&mut padding);
            buf.put(&padding[0..x as usize]);
        }
        buf.put_u32(fnv1a!(&buf) as u32);

        let cmd_key: [u8; 16] = md5!(
            option.uuid.as_bytes(),
            b"c48619fe-8f02-49e0-b9e9-edf763e17e21"
        );

        seal_vmess_aead_header(&cmd_key, &buf)
    }
}

impl<T: AsyncRead + Unpin> VmessStream<T> {
    fn poll_read_header(
        &mut self,
        ctx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // wait resp
        (*self.header_reader).received_resp();
        let res = (*self.header_reader).poll_read_decrypted(ctx, &mut self.stream);
        if res.is_error() {
            return Poll::Pending;
        } else if res.is_ready() {
            // steal buffer
            self.reader.buffer = self.header_reader.get_buffer();
            // streaming
            return self.reader.poll_read_decrypted(ctx, &mut self.stream, dst);
        }
        return Poll::Pending;
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for VmessStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        (*self).poll_read_header(ctx, buf)
    }
}

impl<T: AsyncWrite + Unpin> VmessStream<T> {
    fn priv_poll_write(&mut self, ctx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // 1. write header req
        debug!("vmess try write aead header");
        while self.header_pos < self.header_buffer.len() {
            let res =
                Pin::new(&mut self.stream).poll_write(ctx, &self.header_buffer[self.header_pos..]);
            if res.is_error() {
                debug!("vmess try write aead header error");
            }
            self.header_pos += res.get_poll_res();
            if self.header_pos < self.header_buffer.len() {
                debug!(
                    "vmess header pos:{},header buffer len:{}",
                    self.header_pos,
                    self.header_buffer.len()
                );
                return Poll::Pending;
            }
        }
        // 2. ready to write data
        self.writer.poll_write_encrypted(ctx, &mut self.stream, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for VmessStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        (*self).priv_poll_write(ctx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.stream).poll_flush(ctx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
