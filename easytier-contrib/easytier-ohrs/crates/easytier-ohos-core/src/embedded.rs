use easytier::common::config::{ConfigLoader, NetworkConfigExt, TomlConfigLoader};
use easytier::proto::api::manage::{NetworkConfig, NetworkingMethod};

pub const EMBEDDED_INSTANCE_ID: &str = "9d9ccb7f-71e5-4cb8-9fb1-a18d0845d6a0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeMode {
    Standalone,
    Embedded,
}

impl RuntimeMode {
    pub fn start_network_instance(
        self,
        start_local_socket: impl FnOnce() -> bool,
        start_management_server: impl FnOnce() -> bool,
        start_instance: impl FnOnce() -> bool,
    ) -> bool {
        // Embedded hosts use N-API directly; the independent app's IPC sockets are unnecessary.
        if self == Self::Standalone && (!start_local_socket() || !start_management_server()) {
            return false;
        }
        start_instance()
    }

    pub fn run_standalone_service(self, operation: impl FnOnce() -> bool) -> bool {
        self == Self::Standalone && operation()
    }
}

pub fn is_config_server_config(config: &NetworkConfig) -> bool {
    matches!(
        NetworkingMethod::try_from(config.networking_method.unwrap_or_default())
            .unwrap_or_default(),
        NetworkingMethod::PublicServer
    ) && config
        .public_server_url
        .as_ref()
        .is_some_and(|url| !url.trim().is_empty())
}

pub fn embedded_network_config(
    cfg_json: &str,
    socks5_port: u32,
) -> Result<(NetworkConfig, TomlConfigLoader), String> {
    if socks5_port == 0 || socks5_port > u16::MAX as u32 {
        return Err("invalid embedded SOCKS5 port".to_string());
    }
    let mut config =
        serde_json::from_str::<NetworkConfig>(cfg_json).map_err(|err| err.to_string())?;
    if is_config_server_config(&config) {
        return Err("embedded mode requires a local network config".to_string());
    }
    config.instance_id = Some(EMBEDDED_INSTANCE_ID.to_string());
    config.no_tun = Some(true);
    config.listener_urls.clear();
    config.enable_socks5 = Some(true);
    config.socks5_port = Some(socks5_port as i32);
    let cfg = config.gen_config().map_err(|err| err.to_string())?;
    cfg.set_socks5_portal(Some(
        format!("socks5://127.0.0.1:{socks5_port}")
            .parse()
            .expect("validated embedded SOCKS5 URL"),
    ));
    Ok((config, cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn embedded_start_skips_denied_ipc_and_preserves_instance_result() {
        for started in [true, false] {
            let calls = RefCell::new(Vec::new());
            assert_eq!(
                RuntimeMode::Embedded.start_network_instance(
                    || {
                        calls.borrow_mut().push("local_socket");
                        false
                    },
                    || {
                        calls.borrow_mut().push("management");
                        false
                    },
                    || {
                        calls.borrow_mut().push("instance");
                        started
                    },
                ),
                started,
            );
            assert_eq!(*calls.borrow(), vec!["instance"]);
        }
    }

    #[test]
    fn standalone_start_preserves_ipc_order_and_short_circuits_failures() {
        for (local_ok, management_ok, instance_ok, expected) in [
            (false, true, true, vec!["local_socket"]),
            (true, false, true, vec!["local_socket", "management"]),
            (true, true, false, vec!["local_socket", "management", "instance"]),
            (true, true, true, vec!["local_socket", "management", "instance"]),
        ] {
            let calls = RefCell::new(Vec::new());
            assert_eq!(
                RuntimeMode::Standalone.start_network_instance(
                    || {
                        calls.borrow_mut().push("local_socket");
                        local_ok
                    },
                    || {
                        calls.borrow_mut().push("management");
                        management_ok
                    },
                    || {
                        calls.borrow_mut().push("instance");
                        instance_ok
                    },
                ),
                local_ok && management_ok && instance_ok,
            );
            assert_eq!(*calls.borrow(), expected);
        }
    }

    #[test]
    fn embedded_cleanup_and_restart_skip_standalone_services() {
        for service in ["web_client", "stop_local_socket", "restart_local_socket", "cleanup"] {
            assert!(!RuntimeMode::Embedded.run_standalone_service(|| {
                panic!("embedded lifecycle must not call {service}")
            }));
        }
        for result in [true, false] {
            let calls = RefCell::new(0);
            assert_eq!(
                RuntimeMode::Standalone.run_standalone_service(|| {
                    *calls.borrow_mut() += 1;
                    result
                }),
                result,
            );
            assert_eq!(*calls.borrow(), 1);
        }
    }

    #[test]
    fn embedded_config_forces_loopback_socks_no_tun_and_no_listeners() {
        let (_, cfg) = embedded_network_config(
            r#"{"networking_method":1,"network_name":"office","network_secret":"secret","no_tun":false,"listener_urls":["tcp://0.0.0.0:11010"]}"#,
            17890,
        )
        .unwrap();
        assert!(cfg.get_flags().no_tun);
        assert!(cfg.get_listeners().unwrap_or_default().is_empty());
        assert_eq!(cfg.get_id().to_string(), EMBEDDED_INSTANCE_ID);
        assert_eq!(
            cfg.get_socks5_portal().unwrap().as_str(),
            "socks5://127.0.0.1:17890",
        );
    }

    #[test]
    fn embedded_config_rejects_invalid_port_and_config_server() {
        for port in [0, 65536] {
            assert!(embedded_network_config("{}", port).is_err());
        }
        assert!(
            embedded_network_config(
                r#"{"networking_method":0,"public_server_url":"tcp://server:11010"}"#,
                17890,
            )
            .is_err()
        );
    }
}
