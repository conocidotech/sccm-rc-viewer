# Security Policy

`sccm-rc` is a remote-control client that handles authenticated, encrypted sessions
to managed Windows endpoints. We take security issues seriously.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via **GitHub Private Vulnerability Reporting**:

1. Go to the repository's **Security** tab → **Report a vulnerability**.
2. Describe the issue, affected version/commit, and steps to reproduce.

We aim to acknowledge reports within a few business days and will keep you updated
on remediation. Responsible disclosure is appreciated — please give us reasonable
time to ship a fix before any public disclosure.

## Scope

In scope:
- The viewer and protocol crates in this repository (auth/seal handling, framing,
  channel parsing, order/bitmap decoding, file/clipboard transfer).

Out of scope:
- The target-side SCCM agent (`CcmExec` / `RdpCoreSccm.dll`) — these are Microsoft
  components; report those to Microsoft.
- Vulnerabilities in upstream dependencies — report to the respective project (we
  will help coordinate where the vendored IronRDP copy is involved).

## Supported versions

This project is pre-1.0; security fixes target the latest `main` and the most recent
release.
