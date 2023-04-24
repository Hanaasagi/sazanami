// Copyright (c) 2023, EAimTY
// This code uses code from the "tuic" repository,
// which is licensed under the GPL-3 License.
// "tuic" is available at: https://github.com/EAimTY/tuic
//
//                    GNU GENERAL PUBLIC LICENSE
//                       Version 3, 29 June 2007

// Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
// Everyone is permitted to copy and distribute verbatim copies
// of this license document, but changing it is not allowed.

use std::net::IpAddr;
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::Error;
use bytes::Bytes;
use crossbeam_utils::atomic::AtomicCell;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use quinn::{
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    ClientConfig, Connection as QuinnConnection, Endpoint as QuinnEndpoint, EndpointConfig,
    RecvStream, SendStream, TokioRuntime, TransportConfig, VarInt,
};
use register_count::{Counter, Register};
use rustls::{version, ClientConfig as RustlsClientConfig};
use tokio::{
    sync::{Mutex as AsyncMutex, OnceCell as AsyncOnceCell},
    time,
};
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;
use tuic::Address;
use tuic_quinn::{side, Connect, Connection as Model, Task};
use uuid::Uuid;

use super::utils::*;
use crate::config::TuicConfig;

static ENDPOINT: OnceCell<Mutex<Endpoint>> = OnceCell::new();
static CONNECTION: AsyncOnceCell<AsyncMutex<Connection>> = AsyncOnceCell::const_new();
static TIMEOUT: AtomicCell<Duration> = AtomicCell::new(Duration::from_secs(0));

const DEFAULT_CONCURRENT_STREAMS: usize = 32;

pub struct Endpoint {
    ep: QuinnEndpoint,
    server: ServerAddr,
    uuid: Uuid,
    password: Arc<[u8]>,
    udp_relay_mode: UdpRelayMode,
    zero_rtt_handshake: bool,
    heartbeat: Duration,
    gc_interval: Duration,
    gc_lifetime: Duration,
}

impl Endpoint {
    pub fn set_config(cfg: TuicConfig) -> Result<(), Error> {
        // TODO:
        let certs = super::utils::load_certs(cfg.certificates(), false)?;

        let mut crypto = RustlsClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(certs)
            .with_no_client_auth();

        crypto.alpn_protocols = cfg
            .alpn()
            .into_iter()
            .map(|alpn| alpn.into_bytes())
            .collect();
        // TODO:
        crypto.enable_early_data = true;
        crypto.enable_sni = true;

        let mut config = ClientConfig::new(Arc::new(crypto));
        let mut tp_cfg = TransportConfig::default();

        tp_cfg
            .max_concurrent_bidi_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS as u32))
            .max_concurrent_uni_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS as u32))
            .max_idle_timeout(None);

        // TODO:
        match CongestionControl::Cubic {
            CongestionControl::Cubic => {
                tp_cfg.congestion_controller_factory(Arc::new(CubicConfig::default()))
            }
            CongestionControl::NewReno => {
                tp_cfg.congestion_controller_factory(Arc::new(NewRenoConfig::default()))
            }
            CongestionControl::Bbr => {
                tp_cfg.congestion_controller_factory(Arc::new(BbrConfig::default()))
            }
        };

        config.transport_config(Arc::new(tp_cfg));

        let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))?;
        let mut ep = QuinnEndpoint::new(EndpointConfig::default(), None, socket, TokioRuntime)?;
        ep.set_default_client_config(config);

        let uuid = uuid::Uuid::from_str(cfg.username().unwrap_or(""))?;

        let ep = Self {
            ep,
            server: ServerAddr::new(
                // TODO:
                "localhost".to_string(),
                cfg.port(),
                Some(IpAddr::from_str(cfg.domain())?),
            ),
            uuid,
            password: Arc::from(
                cfg.password()
                    .unwrap_or("")
                    .to_string()
                    .into_bytes()
                    .into_boxed_slice(),
            ),
            udp_relay_mode: UdpRelayMode::Native,
            zero_rtt_handshake: false,
            heartbeat: Duration::from_secs(3),
            gc_interval: Duration::from_secs(3),
            gc_lifetime: Duration::from_secs(15),
        };

        ENDPOINT
            .set(Mutex::new(ep))
            .map_err(|_| "endpoint already initialized")
            .unwrap();

        TIMEOUT.store(Duration::from_secs(1));

        Ok(())
    }

    async fn connect(&mut self) -> Result<Connection, Error> {
        async fn connect_to(
            ep: &mut QuinnEndpoint,
            addr: SocketAddr,
            server_name: &str,
            uuid: Uuid,
            password: Arc<[u8]>,
            udp_relay_mode: UdpRelayMode,
            zero_rtt_handshake: bool,
        ) -> Result<Connection, Error> {
            let match_ipv4 = addr.is_ipv4() && ep.local_addr().map_or(false, |addr| addr.is_ipv4());
            let match_ipv6 = addr.is_ipv6() && ep.local_addr().map_or(false, |addr| addr.is_ipv6());

            if !match_ipv4 && !match_ipv6 {
                let bind_addr = if addr.is_ipv4() {
                    SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
                } else {
                    SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
                };

                ep.rebind(UdpSocket::bind(bind_addr)?)?;
            }

            let conn = ep.connect(addr, server_name)?;
            let conn = if zero_rtt_handshake {
                match conn.into_0rtt() {
                    Ok((conn, _)) => conn,
                    Err(conn) => {
                        debug!("[connection] 0-RTT handshake failed, fallback to 1-RTT handshake");
                        conn.await?
                    }
                }
            } else {
                conn.await?
            };

            Ok(Connection::new(conn, udp_relay_mode, uuid, password))
        }

        let mut last_err = None;

        for addr in self.server.resolve().await? {
            let res = connect_to(
                &mut self.ep,
                addr,
                self.server.server_name(),
                self.uuid,
                self.password.clone(),
                self.udp_relay_mode,
                self.zero_rtt_handshake,
            )
            .await;

            match res {
                Ok(conn) => {
                    debug!("[connection] connection established");
                    tokio::spawn(conn.clone().init(
                        self.heartbeat,
                        self.gc_interval,
                        self.gc_lifetime,
                    ));
                    return Ok(conn);
                }
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or(anyhow::anyhow!("AAAAA")))
    }
}

#[derive(Clone)]
pub struct Connection {
    conn: QuinnConnection,
    model: Model<side::Client>,
    uuid: Uuid,
    password: Arc<[u8]>,
    udp_relay_mode: UdpRelayMode,
    remote_uni_stream_cnt: Counter,
    remote_bi_stream_cnt: Counter,
    max_concurrent_uni_streams: Arc<AtomicUsize>,
    max_concurrent_bi_streams: Arc<AtomicUsize>,
}

impl Connection {
    fn new(
        conn: QuinnConnection,
        udp_relay_mode: UdpRelayMode,
        uuid: Uuid,
        password: Arc<[u8]>,
    ) -> Self {
        Self {
            conn: conn.clone(),
            model: Model::<side::Client>::new(conn),
            uuid,
            password,
            udp_relay_mode,
            remote_uni_stream_cnt: Counter::new(),
            remote_bi_stream_cnt: Counter::new(),
            max_concurrent_uni_streams: Arc::new(AtomicUsize::new(DEFAULT_CONCURRENT_STREAMS)),
            max_concurrent_bi_streams: Arc::new(AtomicUsize::new(DEFAULT_CONCURRENT_STREAMS)),
        }
    }

    pub async fn get() -> Result<Connection, Error> {
        let try_init_conn = async {
            ENDPOINT
                .get()
                .unwrap()
                .lock()
                .connect()
                .await
                .map(AsyncMutex::new)
        };

        let try_get_conn = async {
            let mut conn = CONNECTION
                .get_or_try_init(|| try_init_conn)
                .await?
                .lock()
                .await;

            if conn.is_closed() {
                let new_conn = ENDPOINT.get().unwrap().lock().connect().await?;
                *conn = new_conn;
            }

            Ok::<_, Error>(conn.clone())
        };

        let conn = time::timeout(TIMEOUT.load(), try_get_conn)
            .await
            .map_err(|_| anyhow::anyhow!("timeout"))??;

        Ok(conn)
    }

    pub async fn connect(&self, addr: Address) -> Result<Connect, Error> {
        Ok(self.model.connect(addr).await?)
    }

    pub async fn packet(&self, pkt: Bytes, addr: Address, assoc_id: u16) -> Result<(), Error> {
        match self.udp_relay_mode {
            UdpRelayMode::Native => self.model.packet_native(pkt, addr, assoc_id)?,
            UdpRelayMode::Quic => self.model.packet_quic(pkt, addr, assoc_id).await?,
        }

        Ok(())
    }

    pub async fn dissociate(&self, assoc_id: u16) -> Result<(), Error> {
        self.model.dissociate(assoc_id).await?;
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    async fn accept_uni_stream(&self) -> Result<(RecvStream, Register), Error> {
        let max = self.max_concurrent_uni_streams.load(Ordering::Relaxed);

        if self.remote_uni_stream_cnt.count() == max {
            self.max_concurrent_uni_streams
                .store(max * 2, Ordering::Relaxed);

            self.conn
                .set_max_concurrent_uni_streams(VarInt::from((max * 2) as u32));
        }

        let recv = self.conn.accept_uni().await?;
        let reg = self.remote_uni_stream_cnt.reg();
        Ok((recv, reg))
    }

    async fn accept_bi_stream(&self) -> Result<(SendStream, RecvStream, Register), Error> {
        let max = self.max_concurrent_bi_streams.load(Ordering::Relaxed);

        if self.remote_bi_stream_cnt.count() == max {
            self.max_concurrent_bi_streams
                .store(max * 2, Ordering::Relaxed);

            self.conn
                .set_max_concurrent_bi_streams(VarInt::from((max * 2) as u32));
        }

        let (send, recv) = self.conn.accept_bi().await?;
        let reg = self.remote_bi_stream_cnt.reg();
        Ok((send, recv, reg))
    }

    async fn accept_datagram(&self) -> Result<Bytes, Error> {
        Ok(self.conn.read_datagram().await?)
    }

    async fn handle_bi_stream(self, send: SendStream, recv: RecvStream, _reg: Register) {
        debug!("[connection] incoming bidirectional stream");
        let res = match self.model.accept_bi_stream(send, recv).await {
            Err(err) => Err(Error::from(err)),
            _ => unreachable!(),
        };

        match res {
            Ok(()) => {}
            Err(err) => error!("[connection] {err}"),
        }
    }

    async fn authenticate(self) {
        match self
            .model
            .authenticate(self.uuid, self.password.clone())
            .await
        {
            Ok(()) => debug!("[connection] authentication sent"),
            Err(err) => warn!("[connection] authentication failed: {err}"),
        }
    }

    async fn heartbeat(self, heartbeat: Duration) {
        loop {
            time::sleep(heartbeat).await;

            if self.is_closed() {
                break;
            }

            if self.model.task_connect_count() + self.model.task_associate_count() == 0 {
                continue;
            }

            match self.model.heartbeat().await {
                Ok(()) => debug!("[connection] heartbeat"),
                Err(err) => warn!("[connection] heartbeat error: {err}"),
            }
        }
    }

    async fn collect_garbage(self, gc_interval: Duration, gc_lifetime: Duration) {
        loop {
            time::sleep(gc_interval).await;

            if self.is_closed() {
                break;
            }

            debug!("[connection] packet garbage collection");
            self.model.collect_garbage(gc_lifetime);
        }
    }

    async fn init(self, heartbeat: Duration, gc_interval: Duration, gc_lifetime: Duration) {
        tokio::spawn(self.clone().authenticate());
        tokio::spawn(self.clone().heartbeat(heartbeat));
        tokio::spawn(self.clone().collect_garbage(gc_interval, gc_lifetime));

        let err = loop {
            tokio::select! {
                res = self.accept_bi_stream() => match res {
                    Ok((send, recv, reg)) => tokio::spawn(self.clone().handle_bi_stream(send, recv, reg)),
                    Err(err) => break err,
                },
            };
        };

        error!("[connection] {err}");
    }
}
