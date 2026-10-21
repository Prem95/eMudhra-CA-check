# Patched versions (snapshot 2026-10-21)

Taken from the advisory's table on 2026-10-21. It changes as vendors ship fixes
(Bun and FreeBSD were still pending), so refresh it from
https://emudhra.we-have-a-problem.com/ before you tell anyone a version is
"latest" or "not fixed yet". A **live probe result beats this table**: a client
that rejects both test hosts is fine whatever its version says.

## Operating-system trust stores

| Package | Fixed in |
|---|---|
| Ubuntu `ca-certificates` | 20260816ubuntu0.22.04.1 / 0.24.04.1 / 0.26.04.1 / 0.26.10.1 |
| Debian `ca-certificates` | 20250419~deb12u2 (bookworm), 20250419+deb13u1 (trixie), 20260816+nmu1 (sid) |
| Arch `ca-certificates-mozilla` | 3.131.1-1 |
| Gentoo `ca-certificates` | 20260816.3.125 |
| Fedora `ca-certificates` | 2026.2.92_v9.0.319 |
| Alpine `ca-certificates` | 20261020-r0 |
| Chainguard `ca-certificates` | 20260909-r3 |
| FreeBSD `ca_root_nss` | **pending**: use the manual untrust in platforms.md |
| NSS | 3.131.1 |
| macOS `/etc/ssl/cert.pem` | **no Apple update yet**: use scripts/fix_macos_system_bundle.sh |
| Windows | Microsoft blocked the intermediates on Oct 20 via Windows Update |

## Package managers, runtimes, libraries

| Component | Fixed in | Notes |
|---|---|---|
| curl CA bundle (`cacert.pem` from curl.se) | 2026-10-20 | Also used by many distros and Docker images |
| Homebrew `ca-certificates` | 2026-09-25_1 (2026-10-20 also shipped) | Covers brew OpenSSL, brew Python, wget, and anything else linked to brew OpenSSL |
| Cloudflare CFSSL trust store | 2026.10.1 | |
| Go | 1.27.3, 1.26.10 | On macOS/Windows, Go uses the platform verifier |
| Node.js | 22.23.4, 24.22.1, 26.12.1 | Odd/EOL lines (≤20, 23, 25) get no fix. Homebrew's 26.12.0 already rejected both test hosts in testing |
| Python `certifi` | 2026.10.19 | Every virtualenv has its own copy |
| pip | 26.2.2 | Observed: on macOS, pip 26.x used `truststore` (Apple trust + revocation) and rejected the bad chains. On Linux, pip 25.0.1 in `python:3.12-slim` was **EXPOSED** (HTTP 200) even with a fixed system bundle, because it used its vendored certifi. Apple's pip 21.x (Python 3.9) is exposed and needs `PIP_CERT`. Always probe pip separately |
| uv | 0.13.4 | |
| Rust `rustls-webpki` | 0.103.16 | Older lines (0.101, 0.102) have no fix |
| Rust `webpki-roots` / `webpki-root-certs` | 1.0.10 | 0.26.x is a shim that depends on 1.x |
| Rustup | 1.29.2 | |
| Electron | 44.9.1, 43.8.1, 42.11.16 | Electron apps (Slack, VS Code, Discord, ...) need their own updates |
| Bun | **pending** | `--use-system-ca` did NOT help in testing (still connected). Mitigation: avoid Bun for sensitive traffic on untrusted networks, or proxy through a client that is patched |
| Composer `composer/ca-bundle` | 1.4.16, 1.6.0 | |
| Elixir `castore` | 1.0.22 | |
| Perl `Mozilla::CA` | 20261020 | |
