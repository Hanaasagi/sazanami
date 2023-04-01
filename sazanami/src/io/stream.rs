use std::sync::Arc;
use std::time::Duration;

use tokio::io::copy_bidirectional;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::io::ReadHalf;
use tokio::io::WriteHalf;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

pub trait Stream: AsyncRead + AsyncWrite + Unpin {
    fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf);
}

/// Bridges two TCP stream together by reading bytes from `s1` and writing
/// them to `s2`, and vice versa. Returns an `io::Result` that is `Ok(())` if
/// either connection has been closed, or an `Err` if an I/O error occurs.
// pub async fn bridge_stream<T: AsyncRead + AsyncWrite + Unpin, U: AsyncRead + AsyncWrite + Unpin>(
pub async fn bridge_stream<T: AsyncRead + AsyncWrite + Unpin, U: AsyncRead + AsyncWrite + Unpin>(
    mut stream1: T,
    mut stream2: U,
    read_timeout: Duration,
    write_timeout: Duration,
    buf_size: usize,
) -> std::io::Result<()> {
    copy_bidirectional(&mut stream1, &mut stream2).await;
    return Ok(());
    // TODO:
    // https://stackoverflow.com/questions/71365810/how-to-share-tokionettcpstream-act-on-it-concurrently?rq=1
    let r1 = Arc::new(Mutex::new(stream1));
    let w1 = r1.clone();
    let r2 = Arc::new(Mutex::new(stream2));
    let w2 = r2.clone();
    // let (mut r1, mut w1) = stream1.into_split();
    // let (mut r2, mut w2) = stream2.into_split();

    let pipe1 = async {
        let mut buf = vec![0; buf_size];
        loop {
            let size = { timeout(read_timeout, r1.lock().await.read_buf(&mut buf)).await };
            if size.is_err() {
                continue;
            }
            if size.as_ref().unwrap().is_err() {
                continue;
            }
            let size = size.unwrap().unwrap();
            if size == 0 {
                return;
            }

            {
                timeout(
                    write_timeout,
                    w2.lock().await.write_all(&buf[buf.len() - size..]),
                )
                .await
                .unwrap()
                .unwrap();
            }
        }
    };
    let pipe2 = async {
        let mut buf = vec![0; buf_size];
        loop {
            let size = { timeout(read_timeout, r2.lock().await.read_buf(&mut buf)).await };
            if size.is_err() {
                continue;
            }
            if size.as_ref().unwrap().is_err() {
                continue;
            }
            let size = size.unwrap().unwrap();
            if size == 0 {
                return;
            }
            {
                timeout(
                    write_timeout,
                    w1.lock().await.write_all(&buf[buf.len() - size..]),
                )
                .await
                .unwrap()
                .unwrap();
            }
        }
    };

    tokio::select! {
        _ = pipe1 => {
        }
        _ = pipe2 => {

        }
    }
    Ok(())
}
