//! Drive an IronRDP `ClientConnector` over the sealed SCCM channel.
//!
//! The RDP connection sequence (X.224 → MCS → security → capabilities →
//! finalization) is run sans-IO: IronRDP produces PDU bytes, we seal them
//! and send them through `SccmSession`; we receive sealed frames, unseal
//! them, and feed the RDP bytes back into IronRDP until it reaches the
//! `Connected` state.

use crate::{SccmSession, Grant};
use ironrdp_connector::{
    ClientConnector, ClientConnectorState, Config, ConnectionResult, ConnectorError, Credentials,
    DesktopSize, Sequence, State,
};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use sccm_rc_protocol::{Error, Result};
use std::net::{Ipv4Addr, SocketAddr};
use tracing::{debug, info};

/// Build a Config for an SCCM RC session: standard RDP security (no TLS,
/// no CredSSP) since the outer SecurityFilter already encrypts everything.
pub fn sccm_rdp_config(width: u16, height: u16) -> Config {
    Config {
        desktop_size: DesktopSize { width, height },
        desktop_scale_factor: 0,
        enable_tls: false,
        enable_credssp: false,
        credentials: Credentials::UsernamePassword {
            username: whoami_user(),
            password: String::new(),
        },
        domain: None,
        client_build: 0,
        client_name: "sccm-rc".to_string(),
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        ime_file_name: String::new(),
        bitmap: None,
        dig_product_id: String::new(),
        client_dir: String::new(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        platform: MajorPlatformType::WINDOWS,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        performance_flags: Default::default(),
        license_cache: None,
        timezone_info: Default::default(),
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: false,
        multitransport_flags: None,
    }
}

fn whoami_user() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string())
}

fn map_err(e: ConnectorError) -> Error {
    Error::Protocol(format!("ironrdp: {e}"))
}

/// Run the full RDP connection sequence over the established SCCM session.
/// Returns the negotiated connection result on success.
pub async fn connect_rdp(session: &mut SccmSession, width: u16, height: u16) -> Result<ConnectionResult> {
    if session.grant() == Grant::ViewOnly {
        debug!("session is view-only — input will be rejected by the server");
    }

    let config = sccm_rdp_config(width, height);
    // Client address is only used to fill the Client Info PDU; a placeholder
    // is fine since the real transport is our sealed channel.
    let client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut connector = ClientConnector::new(config, client_addr);

    let mut input_buf: Vec<u8> = Vec::new();
    let mut out = WriteBuf::new();

    loop {
        if connector.state.is_terminal() {
            break;
        }

        out.clear();
        let written = if let Some(hint) = connector.next_pdu_hint() {
            // Accumulate sealed RDP bytes until a full PDU is available.
            let pdu_len = loop {
                match hint.find_size(&input_buf).map_err(|e| Error::Protocol(format!("pdu hint: {e}")))? {
                    Some((_matches, size)) => break size,
                    None => {
                        let more = session
                            .recv_rdp()
                            .await?
                            .ok_or_else(|| Error::Protocol("server closed during RDP connect".into()))?;
                        input_buf.extend_from_slice(&more);
                    }
                }
            };
            let pdu: Vec<u8> = input_buf.drain(..pdu_len).collect();
            debug!(state = connector.state.name(), pdu_len, "RDP step (with input)");
            connector.step(&pdu, &mut out).map_err(map_err)?
        } else {
            debug!(state = connector.state.name(), "RDP step (no input)");
            connector.step_no_input(&mut out).map_err(map_err)?
        };

        let _ = written;
        if out.filled_len() > 0 {
            session.send_rdp(out.filled()).await?;
        }
    }

    if let ClientConnectorState::Connected { result } = connector.state {
        info!(
            width = result.desktop_size.width,
            height = result.desktop_size.height,
            io_channel = result.io_channel_id,
            user_channel = result.user_channel_id,
            "✅ RDP connection sequence complete — active session"
        );
        Ok(result)
    } else {
        Err(Error::Protocol(format!(
            "RDP connector ended in non-connected state: {}",
            connector.state.name()
        )))
    }
}
