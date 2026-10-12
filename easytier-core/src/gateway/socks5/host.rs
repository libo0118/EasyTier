use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    gateway::dataplane::{DataPlaneRuntime, DataPlaneUdpSocket},
    host::dns::{DnsQuery, DnsResolver},
    socket::{
        IpVersion, SocketContext,
        tcp::{VirtualTcpListenerFactory, VirtualTcpSocketFactory},
        udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
    },
};

use super::{
    adapter::map_data_plane_error,
    codec::{AddrError, Result, SocksError, TargetAddr, new_udp_header, parse_udp_request},
    server::{Socks5ServerRuntime, Socks5UdpAssociation},
};

/// Host sockets accept SOCKS traffic; outbound UDP belongs to the overlay data plane.
pub(crate) struct HostSocks5ServerRuntime<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    host: Arc<H>,
    dns: Arc<dyn DnsResolver>,
    socket_context: SocketContext,
    data_plane: Arc<DataPlaneRuntime<H>>,
}

impl<H> HostSocks5ServerRuntime<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    pub fn new(
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        socket_context: SocketContext,
        data_plane: Arc<DataPlaneRuntime<H>>,
    ) -> Self {
        Self {
            host,
            dns,
            socket_context,
            data_plane,
        }
    }

    async fn resolve_target(&self, target: TargetAddr) -> Result<SocketAddr> {
        match target {
            TargetAddr::Ip(address) => Ok(address),
            TargetAddr::Domain(domain, port) => {
                tracing::debug!(%domain, "attempting SOCKS DNS resolution");
                let address = self
                    .dns
                    .resolve(DnsQuery::new(domain.clone(), self.socket_context.clone()))
                    .await
                    .map_err(|error| {
                        SocksError::Other(error.context(AddrError::DNSResolutionFailed))
                    })?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        SocksError::Other(anyhow::Error::new(AddrError::Custom(format!(
                            "cannot resolve SOCKS domain {domain}"
                        ))))
                    })?;
                let address = SocketAddr::new(address, port);
                tracing::debug!(%address, "SOCKS domain resolved");
                Ok(address)
            }
        }
    }

    fn udp_bind_options(&self, local_ip: IpAddr) -> UdpBindOptions {
        let ip_version = if local_ip.is_ipv4() {
            IpVersion::V4
        } else {
            IpVersion::V6
        };
        UdpBindOptions::socks5()
            .with_need_protect(false)
            .with_context(self.socket_context.clone().with_ip_version(ip_version))
            .with_local_addr(Some(SocketAddr::new(local_ip, 0)))
    }
}

#[async_trait::async_trait]
impl<H> Socks5ServerRuntime for HostSocks5ServerRuntime<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    async fn resolve_dns(&self, target_addr: TargetAddr) -> Result<TargetAddr> {
        self.resolve_target(target_addr).await.map(TargetAddr::Ip)
    }

    async fn bind_udp_association(
        &self,
        local_ip: IpAddr,
        client_addr: SocketAddr,
    ) -> Result<Box<dyn Socks5UdpAssociation>> {
        let inbound = self
            .host
            .bind_udp(self.udp_bind_options(local_ip))
            .await
            .map_err(SocksError::Other)?;
        let outbound = self
            .data_plane
            .data_plane_udp_bind(0, Duration::from_secs(10))
            .await
            .map_err(map_data_plane_error)?;
        Ok(Box::new(HostSocks5UdpAssociation {
            inbound,
            outbound,
            expected_client: client_addr,
            client: Mutex::new(None),
        }))
    }
}

struct HostSocks5UdpAssociation<S>
where
    S: VirtualUdpSocket,
{
    inbound: Arc<S>,
    outbound: DataPlaneUdpSocket,
    expected_client: SocketAddr,
    client: Mutex<Option<SocketAddr>>,
}

#[async_trait::async_trait]
impl<S> Socks5UdpAssociation for HostSocks5UdpAssociation<S>
where
    S: VirtualUdpSocket,
{
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inbound.local_addr()
    }

    async fn transfer(self: Box<Self>) -> Result<()> {
        tokio::try_join!(
            transfer_requests(self.as_ref()),
            transfer_responses(self.as_ref()),
        )?;
        Ok(())
    }
}

async fn transfer_requests<S>(association: &HostSocks5UdpAssociation<S>) -> Result<()>
where
    S: VirtualUdpSocket,
{
    let mut buffer = vec![0u8; 0x10000];
    loop {
        let (size, mut client) = association.inbound.recv_from(&mut buffer).await?;
        client.set_ip(client.ip().to_canonical());
        if client.ip() != association.expected_client.ip()
            || (association.expected_client.port() != 0
                && client.port() != association.expected_client.port())
        {
            continue;
        }

        let (fragment, target, data) = match parse_udp_request(&buffer[..size]).await {
            Ok(request) => request,
            Err(error) => {
                tracing::debug!(?error, "discarding malformed SOCKS UDP request");
                continue;
            }
        };
        if fragment != 0 {
            tracing::debug!(fragment, "discarding fragmented SOCKS UDP request");
            continue;
        }
        // shortcut: IPv4 IP targets only, add DNS/IPv6 when the embedded client needs them.
        let target = match target {
            TargetAddr::Ip(SocketAddr::V4(address)) => SocketAddr::V4(address),
            _ => {
                tracing::debug!("discarding unresolved or non-IPv4 SOCKS UDP target");
                continue;
            }
        };

        {
            let mut pinned = association.client.lock().unwrap();
            match *pinned {
                None => *pinned = Some(client),
                Some(current) if current == client => {}
                Some(_) => continue,
            }
        }

        if let Err(error) = association.outbound.send_to(data, target).await {
            tracing::debug!(?error, ?target, "SOCKS UDP send failed");
        }
    }
}

async fn transfer_responses<S>(association: &HostSocks5UdpAssociation<S>) -> Result<()>
where
    S: VirtualUdpSocket,
{
    let mut buffer = vec![0u8; 0x10000];
    loop {
        let (size, remote) = association.outbound.recv_from(&mut buffer).await?;
        let client = *association.client.lock().unwrap();
        let Some(client) = client else {
            continue;
        };
        let mut data = new_udp_header(remote)?;
        data.extend_from_slice(&buffer[..size]);
        association.inbound.send_to(&data, client).await?;
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::Ordering;

    use crate::gateway::socks5::{AcceptAuthentication, AsyncTcpConnector, Config, Socks5Socket};
    use crate::host::testkit::TestHost;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::mpsc;

    struct StaticDns;

    #[async_trait::async_trait]
    impl DnsResolver for StaticDns {
        async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            assert_eq!(query.host, "peer.example");
            Ok(vec!["192.0.2.8".parse().unwrap()])
        }
    }

    struct MockSocket {
        receives: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
        sends: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    }

    #[async_trait::async_trait]
    impl VirtualUdpSocket for MockSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:42000".parse().unwrap())
        }

        async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.sends
                .send((data.to_vec(), addr))
                .map_err(|_| io::Error::other("test UDP response receiver closed"))?;
            Ok(data.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let (data, addr) = self
                .receives
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| io::Error::other("test UDP request sender closed"))?;
            buf[..data.len()].copy_from_slice(&data);
            Ok((data.len(), addr))
        }
    }

    struct TestRuntime {
        inbound: Arc<MockSocket>,
        data_plane: Arc<DataPlaneRuntime<TestHost>>,
    }

    #[async_trait::async_trait]
    impl Socks5ServerRuntime for TestRuntime {
        async fn resolve_dns(&self, target: TargetAddr) -> Result<TargetAddr> {
            Ok(target)
        }

        async fn bind_udp_association(
            &self,
            local_ip: IpAddr,
            client_addr: SocketAddr,
        ) -> Result<Box<dyn Socks5UdpAssociation>> {
            assert_eq!(local_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
            Ok(Box::new(HostSocks5UdpAssociation {
                inbound: self.inbound.clone(),
                outbound: self
                    .data_plane
                    .data_plane_udp_bind(0, Duration::from_secs(10))
                    .await
                    .map_err(map_data_plane_error)?,
                expected_client: client_addr,
                client: Mutex::new(None),
            }))
        }
    }

    struct UnusedConnector;

    #[async_trait::async_trait]
    impl AsyncTcpConnector for UnusedConnector {
        type S = DuplexStream;

        async fn tcp_connect(&self, _addr: SocketAddr, _timeout_s: u64) -> Result<Self::S> {
            panic!("UDP ASSOCIATE must not call the TCP connector")
        }
    }

    async fn associate(
        data_plane: Arc<DataPlaneRuntime<TestHost>>,
        inbound: Arc<MockSocket>,
        requested_client: SocketAddr,
    ) -> (DuplexStream, tokio::task::JoinHandle<Result<()>>) {
        let (server_stream, mut client_stream) = tokio::io::duplex(1024);
        let mut config = Config::<AcceptAuthentication>::default();
        config.set_allow_no_auth(true).set_allow_udp(true);
        let socket = Socks5Socket::new(
            server_stream,
            Arc::new(config),
            UnusedConnector,
            Arc::new(TestRuntime {
                inbound,
                data_plane,
            }),
        )
        .with_udp_context(
            "[::ffff:127.0.0.1]:21000".parse().unwrap(),
            "[::ffff:127.0.0.1]:31000".parse().unwrap(),
        );
        let task = tokio::spawn(async move { socket.upgrade_to_socks5().await.map(|_| ()) });
        client_stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client_stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 3, 0];
        request.extend_from_slice(&new_udp_header(requested_client).unwrap()[3..]);
        client_stream.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        client_stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0, 0, 1, 127, 0, 0, 1, 0xa4, 0x10]);
        (client_stream, task)
    }

    /// Called with two Ring-connected real data planes, so Host UDP cannot pass this test.
    pub(crate) async fn exercise_overlay_udp(
        data_plane: Arc<DataPlaneRuntime<TestHost>>,
        remote: &DataPlaneUdpSocket,
    ) {
        let host = Arc::new(TestHost::default());
        let context = SocketContext::default().with_socket_mark(Some(7));
        let runtime = HostSocks5ServerRuntime::new(
            host.clone(),
            Arc::new(StaticDns),
            context.clone(),
            data_plane.clone(),
        );
        assert_eq!(
            runtime
                .resolve_dns(TargetAddr::Domain("peer.example".into(), 443))
                .await
                .unwrap(),
            TargetAddr::Ip("192.0.2.8:443".parse().unwrap())
        );
        let client: SocketAddr = "127.0.0.1:31000".parse().unwrap();
        for ip in ["127.0.0.1", "::1"] {
            let ip: IpAddr = ip.parse().unwrap();
            let options = runtime.udp_bind_options(ip);
            assert_eq!(options.local_addr, Some(SocketAddr::new(ip, 0)));
            assert_eq!(options.context.socket_mark, context.socket_mark);
            assert!(!options.need_protect, "association listener is inbound");
            assert_eq!(
                options.context.ip_version,
                if ip.is_ipv4() {
                    IpVersion::V4
                } else {
                    IpVersion::V6
                }
            );
        }
        let association = runtime
            .bind_udp_association(client.ip(), client)
            .await
            .unwrap();
        assert_eq!(association.local_addr().unwrap().ip(), client.ip());
        assert_ne!(association.local_addr().unwrap().port(), 0);
        assert_eq!(host.udp_binds.load(Ordering::Relaxed), 1);
        drop(association);

        let (requests, receives) = mpsc::unbounded_channel();
        let (sends, mut responses) = mpsc::unbounded_channel();
        let inbound = Arc::new(MockSocket {
            receives: tokio::sync::Mutex::new(receives),
            sends,
        });
        let target = remote.local_addr();
        let mut valid = new_udp_header(target).unwrap();
        valid.extend_from_slice(b"ping");

        for requested_port in [client.port(), 0] {
            let (control, task) = associate(
                data_plane.clone(),
                inbound.clone(),
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), requested_port),
            )
            .await;
            let mut fragmented = valid.clone();
            fragmented[2] = 1;
            for (data, source) in [
                (valid.clone(), "127.0.0.2:31000".parse().unwrap()),
                (vec![0, 0], "127.0.0.1:31001".parse().unwrap()),
                (fragmented, client),
                (new_udp_header(("peer.example", 53)).unwrap(), client),
                (
                    new_udp_header("[::1]:53".parse::<SocketAddr>().unwrap()).unwrap(),
                    client,
                ),
                (valid.clone(), client),
                (valid.clone(), "127.0.0.1:31001".parse().unwrap()),
            ] {
                requests.send((data, source)).unwrap();
            }
            let mut second = new_udp_header(target).unwrap();
            second.extend_from_slice(b"next");
            requests.send((second, client)).unwrap();

            let mut overlay_port = 0;
            for payload in [b"ping", b"next"] {
                let mut buffer = [0; 64];
                let (size, overlay_source) =
                    tokio::time::timeout(Duration::from_secs(10), remote.recv_from(&mut buffer))
                        .await
                        .expect("SOCKS datagram did not cross the overlay")
                        .unwrap();
                assert_eq!(&buffer[..size], payload);
                assert_ne!(overlay_source.ip(), client.ip());
                overlay_port = overlay_source.port();
                remote.send_to(b"pong", overlay_source).await.unwrap();
                let (response, response_client) =
                    tokio::time::timeout(Duration::from_secs(10), responses.recv())
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(response_client, client);
                assert_eq!(
                    response[3],
                    super::super::codec::consts::SOCKS5_ADDR_TYPE_IPV4
                );
                let (fragment, response_target, data) = parse_udp_request(&response).await.unwrap();
                assert_eq!(fragment, 0);
                assert_eq!(response_target, TargetAddr::Ip(target));
                assert_eq!(data, b"pong");
            }

            if requested_port == 0 {
                data_plane.stop_runtime().await;
                assert!(
                    tokio::time::timeout(Duration::from_secs(1), task)
                        .await
                        .expect("instance stop did not release UDP association")
                        .unwrap()
                        .is_err()
                );
                drop(control);
            } else {
                drop(control);
                assert!(
                    tokio::time::timeout(Duration::from_secs(1), task)
                        .await
                        .expect("TCP close did not release UDP association")
                        .unwrap()
                        .is_ok()
                );
                let reclaimed = data_plane
                    .data_plane_udp_bind(overlay_port, Duration::from_secs(1))
                    .await
                    .expect("TCP close did not release the overlay UDP port");
                drop(reclaimed);
            }
        }
    }
}
