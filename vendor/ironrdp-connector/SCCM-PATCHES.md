# Local patches to ironrdp-connector 0.9.0 for SCCM Remote Control

Vendored copy of `ironrdp-connector` 0.9.0 with minimal changes to allow
**standard RDP security** (encryption level NONE).

## Why

SCCM Remote Control negotiates `PROTOCOL_RDP` (standard RDP security)
because the outer SCCM SecurityFilter (Kerberos GSS sealing) already
provides confidentiality. The inner RDP therefore uses
`encryption_method = NONE` / `encryption_level = None` — there is no RC4
to perform. Upstream IronRDP rejects "standard RDP security" outright
because it (reasonably) assumes standard security means insecure RC4.
In our case it means *no inner encryption*, which is safe: the bytes are
already sealed by the outer layer.

## Patches (all in `src/connection.rs`)

1. **Initiation send** — removed the hard error when the requested
   security protocol is standard RDP security; replaced with a warning.

2. **Initiation wait-confirm** — the `selected_protocol.intersects(
   requested_protocol)` check fails for standard security because it is
   `SecurityProtocol(0x0)` (empty, no bits to intersect). Added a
   `both_standard` bypass.

3. **Basic settings exchange** — added a diagnostic log of the server's
   security data (kept; harmless).

## Verified

Against TARGET-HOST (2026-05-31): the connector drives the entire RDP
connection sequence to an **active session** (1920×1080) over the sealed
SCCM channel. MCS Connect Response confirmed `encryption_method=0x0`,
`encryption_level=None`, `server_cert=[]`.

## Maintenance

When bumping IronRDP, re-apply these 2-3 small diffs. Consider proposing
an upstream `allow_standard_security_no_encryption` config flag.
