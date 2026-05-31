# Local patches to ironrdp-connector 0.8.0 for SCCM Remote Control

Vendored copy with 2 minimal changes to allow standard RDP security
(encryption level NONE), in `src/connection.rs`:

1. Initiation send: removed the hard error on standard RDP security
   (replaced with a warning).
2. Initiation wait-confirm: standard security is SecurityProtocol(0x0),
   so `intersects()` is false even when both agree — added a
   `both_standard` bypass.

## Why it is safe

SCCM inner-RDP uses encryption_method=NONE / encryption_level=None
(confirmed via MCS Connect Response). The outer SCCM SecurityFilter
(Kerberos GSS) provides all confidentiality. There is no RC4 to perform.

## Version

Pinned to the IronRDP 0.8 release set: connector 0.8.0, session 0.8.0,
pdu 0.7, graphics 0.7, core 0.1. Re-apply these 2 diffs when bumping.
