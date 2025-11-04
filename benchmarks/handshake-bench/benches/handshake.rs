use anyhow::{anyhow, Result};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pqq_client::{Client, ClientConfig};
use pqq_core::{build_initial_packet, HandshakeConfig, HandshakeDriver};
use pqq_server::{SecurityProfile, Server, ServerConfig};
use std::{convert::TryFrom, net::SocketAddr, sync::Arc};
use tokio::time::{timeout, Duration};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    runtime::Runtime,
    try_join,
};
use tokio_rustls::{
    rustls,
    TlsAcceptor,
    TlsConnector,
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

#[derive(Clone)]
struct PqqCoreHarness {
    driver: Arc<HandshakeDriver>,
    supported_initial: Arc<Vec<u8>>,
    fallback_initial: Arc<Vec<u8>>,
}

impl PqqCoreHarness {
    fn new() -> Self {
        let driver = Arc::new(HandshakeDriver::new(
            HandshakeConfig::default()
                .with_supported_alpns(["pqq/1"])
                .with_fallback_endpoint("h3", "localhost", 443),
        ));
        let supported_initial = Arc::new(build_initial_packet(["pqq/1", "h3"]));
        let fallback_initial = Arc::new(build_initial_packet(["spdy/3", "h3"]));

        Self {
            driver,
            supported_initial,
            fallback_initial,
        }
    }

    fn run_supported(&self) -> pqq_core::HandshakeResponse {
        self.driver
            .process_initial_datagram(self.supported_initial.as_slice(), None)
            .expect("supported initial packet")
    }

    fn run_fallback(&self) -> pqq_core::HandshakeResponse {
        self.driver
            .process_initial_datagram(self.fallback_initial.as_slice(), None)
            .expect("fallback initial packet")
    }
}

#[derive(Clone)]
struct PqqUdpHarness {
    driver: Arc<HandshakeDriver>,
    socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
}

impl PqqUdpHarness {
    async fn new() -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let server_addr = socket.local_addr()?;
        let driver = Arc::new(HandshakeDriver::new(
            HandshakeConfig::default()
                .with_supported_alpns(["pqq/1"])
                .with_fallback_endpoint("h3", "localhost", 443),
        ));

        Ok(Self {
            driver,
            socket,
            server_addr,
        })
    }

    async fn run(&self, client_alpns: &[&str]) -> Result<()> {
        let server = {
            let driver = Arc::clone(&self.driver);
            let socket = Arc::clone(&self.socket);
            async move {
                driver.run_once(socket.as_ref()).await?;
                Ok::<(), anyhow::Error>(())
            }
        };

        let client = {
            let addr = self.server_addr;
            let mut client_config = ClientConfig::new(addr);
            client_config.handshake = client_config
                .handshake
                .with_supported_alpns(client_alpns.iter().copied());
            let client = Client::new(client_config);
            async move {
                client.probe().await?;
                Ok::<(), anyhow::Error>(())
            }
        };

        timeout(Duration::from_secs(1), async {
            try_join!(server, client)?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .map_err(|_| anyhow!("udp handshake harness timed out"))??;
        Ok(())
    }
}

#[derive(Clone)]
struct HttpsContext {
    acceptor: Arc<TlsAcceptor>,
    connector: Arc<TlsConnector>,
}

impl HttpsContext {
    fn new() -> Result<Self> {
        let cert = rcgen::generate_simple_self_signed(["localhost".into()])?;
        let cert_der = CertificateDer::from(cert.serialize_der()?);
        let key_der: PrivateKeyDer<'static> =
            PrivatePkcs8KeyDer::from(cert.serialize_private_key_der()).into();

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)?;
        server_config.alpn_protocols.push(b"h3".to_vec());

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der.clone())?;
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.alpn_protocols.push(b"h3".to_vec());

        Ok(Self {
            acceptor: Arc::new(TlsAcceptor::from(Arc::new(server_config))),
            connector: Arc::new(TlsConnector::from(Arc::new(client_config))),
        })
    }

    async fn run_handshake(&self) -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let acceptor = Arc::clone(&self.acceptor);
        let connector = Arc::clone(&self.connector);

        let server = async move {
            let (stream, _) = listener.accept().await?;
            acceptor.accept(stream).await?;
            Ok::<(), anyhow::Error>(())
        };

        let client = async move {
            let stream = TcpStream::connect(addr).await?;
            let server_name = ServerName::try_from("localhost")
                .map_err(|_| anyhow::anyhow!("invalid server name"))?;
            connector.connect(server_name, stream).await?;
            Ok::<(), anyhow::Error>(())
        };

        try_join!(server, client)?;
        Ok(())
    }
}

async fn run_velocity_handshake(profile: SecurityProfile) -> Result<()> {
    let handshake = async move {
        let server = Server::bind(
            ([127, 0, 0, 1], 0),
            ServerConfig::default()
                .with_security_profile(profile)
                .with_alpn(["pqq/1"]),
        )
        .await?;
        let addr = server.local_addr()?;
        let kem_public = server.kem_public_key().to_vec();

        let server_future = async move {
            server
                .accept()
                .await
                .map(|_| ())
                .map_err(anyhow::Error::from)
        };

        let client_future = async move {
            let client = Client::new(
                ClientConfig::new(addr)
                    .with_alpns(["pqq/1"])
                    .with_security_profile(profile)
                    .with_server_kem_public(kem_public),
            );
            client
                .connect()
                .await
                .map(|_| ())
                .map_err(anyhow::Error::from)
        };

        tokio::try_join!(server_future, client_future)?;
        Ok::<(), anyhow::Error>(())
    };

    timeout(Duration::from_secs(1), handshake)
        .await
        .map_err(|_| anyhow!("velocity {profile:?} handshake timed out"))??;
    Ok(())
}

fn handshake_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake-negotiation");
    let https_ctx = HttpsContext::new().expect("https context");
    let core_harness = Arc::new(PqqCoreHarness::new());
    let runtime = Arc::new(Runtime::new().expect("tokio runtime"));
    let udp_harness = runtime
        .block_on(PqqUdpHarness::new())
        .expect("pqq udp harness");
    let udp_harness = Arc::new(udp_harness);

    group.bench_function("pqq-supported", |b| {
        let harness = Arc::clone(&core_harness);
        b.iter(|| {
            black_box(harness.run_supported());
        })
    });

    group.bench_function("fallback-h3", |b| {
        let harness = Arc::clone(&core_harness);
        b.iter(|| {
            black_box(harness.run_fallback());
        })
    });

    group.bench_function("pqq-udp-supported", |b| {
        let rt = Arc::clone(&runtime);
        let harness = Arc::clone(&udp_harness);
        b.iter(|| {
            rt.block_on(harness.run(&["pqq/1", "h3"]))
                .expect("pqq udp handshake");
        })
    });

    group.bench_function("fallback-h3-udp", |b| {
        let rt = Arc::clone(&runtime);
        let harness = Arc::clone(&udp_harness);
        b.iter(|| {
            rt.block_on(harness.run(&["spdy/3", "h3"]))
                .expect("fallback udp handshake");
        })
    });

    group.bench_function("https-tls13", |b| {
        let rt = Arc::clone(&runtime);
        let ctx = https_ctx.clone();
        b.iter(|| {
            rt.block_on(ctx.run_handshake()).expect("https handshake");
        })
    });

    for (label, profile) in [
        ("velocity-turbo", SecurityProfile::Turbo),
        ("velocity-balanced", SecurityProfile::Balanced),
        ("velocity-fortress", SecurityProfile::Fortress),
    ] {
        let rt = Arc::clone(&runtime);
        group.bench_function(label, move |b| {
            b.iter(|| {
                rt.block_on(run_velocity_handshake(profile))
                    .expect("velocity handshake");
            })
        });
    }
    group.finish();
}

criterion_group!(benches, handshake_benches);
criterion_main!(benches);
