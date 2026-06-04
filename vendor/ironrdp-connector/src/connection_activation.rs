use core::mem;

use ironrdp_pdu::rdp;
use ironrdp_pdu::rdp::capability_sets::CapabilitySet;
use tracing::{debug, warn};

use crate::{
    general_err, legacy, Config, ConnectionFinalizationSequence, ConnectorResult, DesktopSize, Sequence, State, Written,
};

/// Represents the Capability Exchange and Connection Finalization phases
/// of the connection sequence (section [1.3.1.1]).
///
/// This is abstracted into its own struct to allow it to be used for the ordinary
/// RDP connection sequence [`ClientConnector`] that occurs for every RDP connection,
/// as well as the Deactivation-Reactivation Sequence ([1.3.1.3]) that occurs when
/// a [Server Deactivate All PDU] is received.
///
/// [1.3.1.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee
/// [1.3.1.3]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dfc234ce-481a-4674-9a5d-2a7bafb14432
/// [`ClientConnector`]: crate::ClientConnector
/// [Server Deactivate All PDU]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8a29971a-df3c-48da-add2-8ed9a05edc89
#[derive(Debug, Clone)]
pub struct ConnectionActivationSequence {
    // PATCHED for sccm-rc: made `state` pub so the client can detect the
    // Finalized state and extract its fields after a reactivation.
    pub state: ConnectionActivationState,
    config: Config,
}

impl ConnectionActivationSequence {
    pub fn new(config: Config, io_channel_id: u16, user_channel_id: u16) -> Self {
        Self {
            state: ConnectionActivationState::CapabilitiesExchange {
                io_channel_id,
                user_channel_id,
            },
            config,
        }
    }

    /// Returns the current state as a district type, rather than `&dyn State` provided by [`Self::state`].
    pub fn connection_activation_state(&self) -> ConnectionActivationState {
        self.state
    }

    #[must_use]
    pub fn reset_clone(&self) -> Self {
        self.clone().reset()
    }

    fn reset(mut self) -> Self {
        match &self.state {
            ConnectionActivationState::CapabilitiesExchange {
                io_channel_id,
                user_channel_id,
            }
            | ConnectionActivationState::ConnectionFinalization {
                io_channel_id,
                user_channel_id,
                ..
            }
            | ConnectionActivationState::Finalized {
                io_channel_id,
                user_channel_id,
                ..
            } => {
                self.state = ConnectionActivationState::CapabilitiesExchange {
                    io_channel_id: *io_channel_id,
                    user_channel_id: *user_channel_id,
                };

                self
            }
            ConnectionActivationState::Consumed => self,
        }
    }
}

impl Sequence for ConnectionActivationSequence {
    fn next_pdu_hint(&self) -> Option<&dyn ironrdp_pdu::PduHint> {
        match &self.state {
            ConnectionActivationState::Consumed => None,
            ConnectionActivationState::Finalized { .. } => None,
            ConnectionActivationState::CapabilitiesExchange { .. } => Some(&ironrdp_pdu::X224_HINT),
            ConnectionActivationState::ConnectionFinalization {
                connection_finalization,
                ..
            } => connection_finalization.next_pdu_hint(),
        }
    }

    fn state(&self) -> &dyn State {
        &self.state
    }

    fn step(&mut self, input: &[u8], output: &mut ironrdp_core::WriteBuf) -> ConnectorResult<Written> {
        let (written, next_state) = match mem::take(&mut self.state) {
            ConnectionActivationState::Consumed | ConnectionActivationState::Finalized { .. } => {
                return Err(general_err!(
                    "connector sequence state is finalized or consumed (this is a bug)"
                ));
            }
            ConnectionActivationState::CapabilitiesExchange {
                io_channel_id,
                user_channel_id,
            } => {
                debug!("Capabilities Exchange");

                let send_data_indication_ctx = legacy::decode_send_data_indication(input)?;
                let share_control_ctx = legacy::decode_share_control(send_data_indication_ctx)?;

                debug!(message = ?share_control_ctx.pdu, "Received");

                if share_control_ctx.channel_id != io_channel_id {
                    warn!(
                        io_channel_id,
                        share_control_ctx.channel_id, "Unexpected channel ID for received Share Control Pdu"
                    );
                }

                let capability_sets = if let rdp::headers::ShareControlPdu::ServerDemandActive(server_demand_active) =
                    share_control_ctx.pdu
                {
                    server_demand_active.pdu.capability_sets
                } else {
                    return Err(general_err!(
                        "unexpected Share Control Pdu (expected ServerDemandActive)",
                    ));
                };

                for c in &capability_sets {
                    if let CapabilitySet::General(g) = c {
                        if g.protocol_version != rdp::capability_sets::PROTOCOL_VER {
                            warn!(version = g.protocol_version, "Unexpected protocol version");
                        }
                        break;
                    }
                }

                // At this point we have already sent a requested desktop size to the server -- either as a part of the
                // [`TS_UD_CS_CORE`] (on initial connection) or the [`DISPLAYCONTROL_MONITOR_LAYOUT`] (on resize event).
                //
                // The server is therefore responding with a desktop size here, which will be close to the requested size but
                // may be slightly different due to server-side constraints. We should use this negotiated size for the rest of
                // the session.
                //
                // [TS_UD_CS_CORE]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/00f1da4a-ee9c-421a-852f-c19f92343d73
                // [DISPLAYCONTROL_MONITOR_LAYOUT]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedisp/ea2de591-9203-42cd-9908-be7a55237d1c
                let desktop_size = capability_sets
                    .iter()
                    .find_map(|c| match c {
                        CapabilitySet::Bitmap(b) => Some(DesktopSize {
                            width: b.desktop_width,
                            height: b.desktop_height,
                        }),
                        _ => None,
                    })
                    .unwrap_or(DesktopSize {
                        width: self.config.desktop_size.width,
                        height: self.config.desktop_size.height,
                    });

                let client_confirm_active = rdp::headers::ShareControlPdu::ClientConfirmActive(
                    create_client_confirm_active(&self.config, capability_sets, desktop_size),
                );

                debug!(message = ?client_confirm_active, "Send");

                // PATCHED for sccm-rc: SCCM_RC_MSTSC_CAPS=1 replaces IronRDP's
                // ConfirmActive with the captured real-CmRcViewer ConfirmActive
                // (byte-exact mstscax capability set + "MSTSC" source descriptor),
                // patched for this session's pduSource / shareId / desktop size.
                // The 2014 SCCM server withholds desktop graphics unless the client
                // advertises mstscax's exact caps; this removes caps as a variable.
                let written = if std::env::var("SCCM_RC_MSTSC_CAPS").as_deref() == Ok("1") {
                    encode_mstsc_confirm_active(
                        user_channel_id,
                        io_channel_id,
                        share_control_ctx.share_id,
                        desktop_size,
                        output,
                    )?
                } else {
                    legacy::encode_share_control(
                        user_channel_id,
                        io_channel_id,
                        share_control_ctx.share_id,
                        client_confirm_active,
                        output,
                    )?
                };

                (
                    Written::from_size(written)?,
                    ConnectionActivationState::ConnectionFinalization {
                        io_channel_id,
                        user_channel_id,
                        desktop_size,
                        connection_finalization: ConnectionFinalizationSequence::new(io_channel_id, user_channel_id),
                    },
                )
            }
            ConnectionActivationState::ConnectionFinalization {
                io_channel_id,
                user_channel_id,
                desktop_size,
                mut connection_finalization,
            } => {
                debug!("Connection Finalization");

                let written = connection_finalization.step(input, output)?;

                let next_state = if !connection_finalization.state.is_terminal() {
                    ConnectionActivationState::ConnectionFinalization {
                        io_channel_id,
                        user_channel_id,
                        desktop_size,
                        connection_finalization,
                    }
                } else {
                    ConnectionActivationState::Finalized {
                        io_channel_id,
                        user_channel_id,
                        desktop_size,
                        enable_server_pointer: self.config.enable_server_pointer,
                        pointer_software_rendering: self.config.pointer_software_rendering,
                    }
                };

                (written, next_state)
            }
        };

        self.state = next_state;

        Ok(written)
    }
}

#[derive(Default, Debug, Copy, Clone)]
pub enum ConnectionActivationState {
    #[default]
    Consumed,
    CapabilitiesExchange {
        io_channel_id: u16,
        user_channel_id: u16,
    },
    ConnectionFinalization {
        io_channel_id: u16,
        user_channel_id: u16,
        desktop_size: DesktopSize,
        connection_finalization: ConnectionFinalizationSequence,
    },
    Finalized {
        io_channel_id: u16,
        user_channel_id: u16,
        desktop_size: DesktopSize,
        enable_server_pointer: bool,
        pointer_software_rendering: bool,
    },
}

impl State for ConnectionActivationState {
    fn name(&self) -> &'static str {
        match self {
            ConnectionActivationState::Consumed => "Consumed",
            ConnectionActivationState::CapabilitiesExchange { .. } => "CapabilitiesExchange",
            ConnectionActivationState::ConnectionFinalization { .. } => "ConnectionFinalization",
            ConnectionActivationState::Finalized { .. } => "Finalized",
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(self, ConnectionActivationState::Finalized { .. })
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

const DEFAULT_POINTER_CACHE_SIZE: u16 = 32;

fn create_client_confirm_active(
    config: &Config,
    mut server_capability_sets: Vec<CapabilitySet>,
    desktop_size: DesktopSize,
) -> rdp::capability_sets::ClientConfirmActive {
    use ironrdp_pdu::rdp::capability_sets::{
        client_codecs_capabilities, Bitmap, BitmapCache, BitmapCacheRev2, BitmapDrawingFlags, Brush, CacheDefinition,
        CacheEntry, CacheFlags, CellInfo, ClientConfirmActive, CmdFlags, DemandActive, FrameAcknowledge, General,
        GeneralExtraFlags, GlyphCache, GlyphSupportLevel, Input, InputFlags, LargePointer, LargePointerSupportFlags,
        MultifragmentUpdate, OffscreenBitmapCache, Order, OrderFlags, OrderSupportExFlags, Pointer, Sound, SoundFlags,
        SupportLevel, SurfaceCommands, VirtualChannel, VirtualChannelFlags, BITMAP_CACHE_ENTRIES_NUM, GLYPH_CACHE_NUM,
        SERVER_CHANNEL_ID,
    };

    server_capability_sets.retain(|capability_set| matches!(capability_set, CapabilitySet::MultiFragmentUpdate(_)));

    let lossy_bitmap_compression = config
        .bitmap
        .as_ref()
        .map(|bitmap| bitmap.lossy_compression)
        .unwrap_or(false);

    let drawing_flags = if lossy_bitmap_compression {
        BitmapDrawingFlags::ALLOW_SKIP_ALPHA
            | BitmapDrawingFlags::ALLOW_DYNAMIC_COLOR_FIDELITY
            | BitmapDrawingFlags::ALLOW_COLOR_SUBSAMPLING
    } else {
        BitmapDrawingFlags::ALLOW_SKIP_ALPHA
    };

    // PATCHED for sccm-rc: drawing-order mode (SCCM_RC_ORDERS=1) advertises
    // MemBlt + a populated rev1 bitmap cache so the SCCM server paints via
    // drawing orders that sccm-rc-orders renders.
    let orders_mode = std::env::var("SCCM_RC_ORDERS").as_deref() == Ok("1");
    // MemBlt needs a bitmap cache. We advertise a Bitmap Cache Rev2 cap (like
    // mstscax) — a populated Rev1 cap made the server reject with ConnectFailed,
    // Rev2 is accepted. On by default in orders mode; SCCM_RC_NO_MEMBLT=1 opts
    // out (A/B: non-cache orders only). The literal Rev1 BitmapCache below stays
    // empty and is replaced by Rev2 in the post-step.
    let want_memblt = orders_mode && std::env::var("SCCM_RC_NO_MEMBLT").as_deref() != Ok("1");
    let bitmap_cache_caches = [CacheEntry::default(); BITMAP_CACHE_ENTRIES_NUM];

    // In orders mode advertise a mstscax-like glyph cache + offscreen cache. The
    // lock screen is text-heavy; a server may refuse to paint to a client that
    // advertises GlyphSupportLevel::None. (Gated via orders_mode.)
    let (glyph_array, glyph_frag, glyph_level) = if orders_mode {
        (
            [
                CacheDefinition { entries: 254, max_cell_size: 4 },
                CacheDefinition { entries: 254, max_cell_size: 4 },
                CacheDefinition { entries: 254, max_cell_size: 8 },
                CacheDefinition { entries: 254, max_cell_size: 8 },
                CacheDefinition { entries: 254, max_cell_size: 16 },
                CacheDefinition { entries: 254, max_cell_size: 32 },
                CacheDefinition { entries: 254, max_cell_size: 64 },
                CacheDefinition { entries: 254, max_cell_size: 128 },
                CacheDefinition { entries: 254, max_cell_size: 256 },
                CacheDefinition { entries: 64, max_cell_size: 256 },
            ],
            CacheDefinition { entries: 256, max_cell_size: 256 },
            GlyphSupportLevel::Full,
        )
    } else {
        (
            [CacheDefinition::default(); GLYPH_CACHE_NUM],
            CacheDefinition::default(),
            GlyphSupportLevel::None,
        )
    };
    let offscreen_cap = if orders_mode {
        OffscreenBitmapCache { is_supported: true, cache_size: 7680, cache_entries: 100 }
    } else {
        OffscreenBitmapCache { is_supported: false, cache_size: 0, cache_entries: 0 }
    };

    server_capability_sets.extend_from_slice(&[
        CapabilitySet::General(General {
            major_platform_type: config.platform,
            extra_flags: GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED | GeneralExtraFlags::NO_BITMAP_COMPRESSION_HDR,
            ..Default::default()
        }),
        CapabilitySet::Bitmap(Bitmap {
            pref_bits_per_pix: 32,
            desktop_width: desktop_size.width,
            desktop_height: desktop_size.height,
            // This is required to be true in order for the Microsoft::Windows::RDS::DisplayControl DVC to work.
            desktop_resize_flag: true,
            drawing_flags,
        }),
        // PATCHED for sccm-rc: advertise primary drawing-order support (like
        // mstscax). The 2014 SCCM RDP server only starts sending graphics to an
        // order-capable client. Our sccm-rc-orders renderer paints these.
        // (Gated on SCCM_RC_ORDERS=1.)
        {
            use ironrdp_pdu::rdp::capability_sets::OrderSupportIndex as Osi;
            // In orders mode mirror the server's Order cap flags + desktop save
            // size (it advertises COLOR_INDEX_SUPPORT | ORDER_FLAGS_EXTRA_FLAGS,
            // desktop_save_size=1000000). A well-behaved client confirms
            // compatible flags.
            let order_flags = if orders_mode {
                OrderFlags::NEGOTIATE_ORDER_SUPPORT
                    | OrderFlags::ZERO_BOUNDS_DELTAS_SUPPORT
                    | OrderFlags::COLOR_INDEX_SUPPORT
                    | OrderFlags::ORDER_FLAGS_EXTRA_FLAGS
            } else {
                OrderFlags::NEGOTIATE_ORDER_SUPPORT | OrderFlags::ZERO_BOUNDS_DELTAS_SUPPORT
            };
            let mut order = Order::new(
                order_flags,
                OrderSupportExFlags::empty(),
                if orders_mode { 1_000_000 } else { 0 },
                0,
            );
            if orders_mode {
                // Non-cache orders our renderer services (OpaqueRect is always
                // supported implicitly, no flag). MemBlt is gated separately.
                for f in [Osi::DstBlt, Osi::PatBlt, Osi::ScrBlt, Osi::LineTo] {
                    order.set_support_flag(f, true);
                }
                if want_memblt {
                    order.set_support_flag(Osi::MemBlt, true);
                }
            }
            CapabilitySet::Order(order)
        },
        // PATCHED for sccm-rc: when advertising MemBlt the bitmap cache MUST
        // have non-zero capacity, otherwise the server rejects the inconsistent
        // capability set (the cause of the Terminate). These are the classic
        // mstsc rev1 cache dimensions; advertising the rev1 cache steers the
        // server to Cache Bitmap Rev1 secondary orders (which we decode).
        CapabilitySet::BitmapCache(BitmapCache {
            caches: bitmap_cache_caches,
        }),
        CapabilitySet::Input(Input {
            input_flags: InputFlags::all(),
            keyboard_layout: 0,
            keyboard_type: Some(config.keyboard_type),
            keyboard_subtype: config.keyboard_subtype,
            keyboard_function_key: config.keyboard_functional_keys_count,
            keyboard_ime_filename: config.ime_file_name.clone(),
        }),
        CapabilitySet::Pointer(Pointer {
            // Pointer cache should be set to non-zero value to enable client-side pointer rendering.
            color_pointer_cache_size: DEFAULT_POINTER_CACHE_SIZE,
            pointer_cache_size: DEFAULT_POINTER_CACHE_SIZE,
        }),
        CapabilitySet::Brush(Brush {
            support_level: SupportLevel::Default,
        }),
        CapabilitySet::GlyphCache(GlyphCache {
            glyph_cache: glyph_array,
            frag_cache: glyph_frag,
            glyph_support_level: glyph_level,
        }),
        CapabilitySet::OffscreenBitmapCache(offscreen_cap),
        CapabilitySet::VirtualChannel(VirtualChannel {
            flags: VirtualChannelFlags::NO_COMPRESSION,
            chunk_size: Some(0), // ignored
        }),
        CapabilitySet::Sound(Sound {
            flags: SoundFlags::empty(),
        }),
        CapabilitySet::LargePointer(LargePointer {
            // Setting `LargePointerSupportFlags::UP_TO_384X384_PIXELS` allows server to send
            // `TS_FP_LARGEPOINTERATTRIBUTE` update messages, which are required for client-side
            // rendering of pointers bigger than 96x96 pixels.
            // `LargePointerSupportFlags::UP_TO_96X96_PIXELS` is needed for proper cursor behavior
            // in Windows 2019 and older
            flags: LargePointerSupportFlags::UP_TO_96X96_PIXELS | LargePointerSupportFlags::UP_TO_384X384_PIXELS,
        }),
        // PATCHED for sccm-rc: the 2014-era SCCM RDP server does not paint
        // when modern Surface Commands / RemoteFx are advertised. Omitting them
        // forces the server to use legacy slow-path Bitmap Update PDUs, which
        // IronRDP also decodes. (Toggle SCCM_RC_LEGACY_GFX=0 to restore modern.)
        CapabilitySet::SurfaceCommands(SurfaceCommands {
            flags: CmdFlags::SET_SURFACE_BITS | CmdFlags::STREAM_SURFACE_BITS | CmdFlags::FRAME_MARKER,
        }),
        CapabilitySet::BitmapCodecs(match config.bitmap.as_ref().map(|b| b.codecs.clone()) {
            Some(codecs) => codecs,
            None => client_codecs_capabilities(&[]).expect("can't panic for &[]"),
        }),
        CapabilitySet::FrameAcknowledge(FrameAcknowledge {
            // FIXME(#447): Revert this to 2 per FreeRDP.
            // This is a temporary hack to fix a resize bug, see:
            // https://github.com/Devolutions/IronRDP/issues/447
            max_unacknowledged_frame_count: 20,
        }),
    ]);

    // PATCHED for sccm-rc: in MemBlt mode replace the (empty) Rev1 bitmap cache
    // with a Bitmap Cache Rev2 capability, as mstscax does. The server rejected
    // a populated Rev1 cache with ConnectFailed. Rev2 also steers the server to
    // Cache Bitmap Rev2 secondary orders. Non-persistent, mstsc/FreeRDP cell
    // dimensions.
    if orders_mode && want_memblt {
        server_capability_sets.retain(|c| !matches!(c, CapabilitySet::BitmapCache(_)));
        // PERSISTENT_KEYS_EXPECTED makes the server wait for a Persistent Key
        // List PDU before painting (some servers require it). Gated for A/B.
        let mut cache_flags = CacheFlags::ALLOW_CACHE_WAITING_LIST_FLAG;
        if std::env::var("SCCM_RC_PERSIST").as_deref() == Ok("1") {
            cache_flags |= CacheFlags::PERSISTENT_KEYS_EXPECTED_FLAG;
        }
        server_capability_sets.push(CapabilitySet::BitmapCacheRev2(BitmapCacheRev2 {
            cache_flags,
            num_cell_caches: 5,
            cache_cell_info: [
                CellInfo { num_entries: 600, is_cache_persistent: false },
                CellInfo { num_entries: 600, is_cache_persistent: false },
                CellInfo { num_entries: 2048, is_cache_persistent: false },
                CellInfo { num_entries: 4096, is_cache_persistent: false },
                CellInfo { num_entries: 2048, is_cache_persistent: false },
            ],
        }));
    }

    // PATCHED for sccm-rc: when SCCM_RC_LEGACY_GFX=1, drop the modern
    // Surface Commands + RemoteFx codec caps so the legacy SCCM RDP server
    // falls back to slow-path Bitmap Update PDUs.
    if std::env::var("SCCM_RC_LEGACY_GFX").as_deref() == Ok("1") {
        server_capability_sets.retain(|c| {
            !matches!(
                c,
                CapabilitySet::SurfaceCommands(_) | CapabilitySet::BitmapCodecs(_)
            )
        });
    }

    if !server_capability_sets
        .iter()
        .any(|c| matches!(&c, CapabilitySet::MultiFragmentUpdate(_)))
    {
        server_capability_sets.push(CapabilitySet::MultiFragmentUpdate(MultifragmentUpdate {
            max_request_size: 8 * 1024 * 1024, // 8 MB
        }));
    }

    ClientConfirmActive {
        originator_id: SERVER_CHANNEL_ID,
        pdu: DemandActive {
            source_descriptor: "IRONRDP".to_owned(),
            capability_sets: server_capability_sets,
        },
    }
}

// PATCHED for sccm-rc: byte-exact replay of the real CmRcViewer's Client
// ConfirmActive (captured 2026-06-03, experiments/captures/DECODE.md). This is a
// standard RDP ConfirmActive PDU: Share Control Header + ConfirmActive body with
// source descriptor "MSTSC" and mstscax's 21 capability sets. We replay it verbatim
// so the SCCM server sees the exact caps it expects, patching only the session
// fields: pduSource (offset 4), shareId (6), and the Bitmap cap desktop size.
const MSTSC_CONFIRM_ACTIVE: &[u8] = &[
    0xea, 0x01, 0x13, 0x00, 0xf4, 0x03, 0xea, 0x03, 0x01, 0x00, 0xea, 0x03, 0x06, 0x00, 0xd4, 0x01,
    0x4d, 0x53, 0x54, 0x53, 0x43, 0x00, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00, 0x01, 0x00,
    0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x1d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x1c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x70, 0x04,
    0x58, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00,
    0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xaa, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xa1, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xe4, 0x04, 0x00, 0x00, 0x13, 0x00, 0x28, 0x00, 0x02, 0x00, 0x00, 0x03, 0x78, 0x00,
    0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x51, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x05, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x08, 0x00,
    0x0a, 0x00, 0x01, 0x00, 0x14, 0x00, 0x15, 0x00, 0x09, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0d, 0x00, 0x58, 0x00, 0xb1, 0x00, 0x00, 0x00, 0x09, 0x04, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x0e, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x34, 0x00, 0xfe, 0x00, 0x04, 0x00,
    0xfe, 0x00, 0x04, 0x00, 0xfe, 0x00, 0x08, 0x00, 0xfe, 0x00, 0x08, 0x00, 0xfe, 0x00, 0x10, 0x00,
    0xfe, 0x00, 0x20, 0x00, 0xfe, 0x00, 0x40, 0x00, 0xfe, 0x00, 0x80, 0x00, 0xfe, 0x00, 0x00, 0x01,
    0x40, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x08, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14, 0x64, 0x00,
    0x14, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x0c, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x1a, 0x00, 0x08, 0x00, 0x2b, 0x48, 0x09, 0x00,
    0x1c, 0x00, 0x0c, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x06, 0x00,
    0x01, 0x00, 0x1e, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
];

/// A raw, pre-encoded PDU body (we already hold the exact bytes).
struct RawPdu<'a>(&'a [u8]);

impl ironrdp_core::Encode for RawPdu<'_> {
    fn encode(&self, dst: &mut ironrdp_core::WriteCursor<'_>) -> ironrdp_core::EncodeResult<()> {
        dst.write_slice(self.0);
        Ok(())
    }
    fn name(&self) -> &'static str {
        "RawMstscConfirmActive"
    }
    fn size(&self) -> usize {
        self.0.len()
    }
}

/// Emit the captured mstscax Client ConfirmActive over the I/O channel, patched
/// for this session (pduSource, shareId, Bitmap-cap desktop size).
fn encode_mstsc_confirm_active(
    user_channel_id: u16,
    io_channel_id: u16,
    share_id: u32,
    desktop_size: DesktopSize,
    output: &mut ironrdp_core::WriteBuf,
) -> ConnectorResult<usize> {
    let mut pdu = MSTSC_CONFIRM_ACTIVE.to_vec();
    // pduSource (Share Control Header) and shareId (ConfirmActive body).
    pdu[4..6].copy_from_slice(&user_channel_id.to_le_bytes());
    pdu[6..10].copy_from_slice(&share_id.to_le_bytes());
    // Patch the Bitmap capability's desktopWidth/Height (captured 1136x600) to the
    // session's negotiated size. Located by its unique captured byte pattern.
    let captured = [0x70u8, 0x04, 0x58, 0x02]; // 1136 x 600, LE
    if let Some(pos) = pdu.windows(4).position(|w| w == captured) {
        pdu[pos..pos + 2].copy_from_slice(&desktop_size.width.to_le_bytes());
        pdu[pos + 2..pos + 4].copy_from_slice(&desktop_size.height.to_le_bytes());
    }
    legacy::encode_send_data_request(user_channel_id, io_channel_id, &RawPdu(&pdu), output)
}
