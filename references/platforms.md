# Remediation by platform and component

Contents: [Order of operations](#order) · [macOS](#macos) · [Linux](#linux) ·
[BSD](#bsd) · [Windows](#windows) · [Embedded bundles](#embedded) ·
[Containers and CI](#containers) · [Rollback](#rollback)

All commands that change trust stores need root. Apply them only after the user
agrees, and back up first. The Linux and BSD commands are copied from the
advisory (2026-10-21). Prefer the distro's fixed package when one exists. The
advisory itself calls manual distrust on Linux "NOT recommended for ordinary
users", because it drops roots that some legitimate sites still use.

<a name="order"></a>
## Order of operations (safest first)

1. **Update packages** (`ca-certificates`, runtimes, libraries) to the fixed
   versions. This is reversible and the vendor has tested it.
2. **Rebuild or refresh copies of the roots**: virtualenvs, the uv/pip cache,
   conda envs, Docker images, vendored bundles in apps.
3. **Manually distrust roots** only where no update exists yet (macOS
   `/etc/ssl/cert.pem`, FreeBSD, unpatched distros).
4. **Mitigate** what cannot be fixed (Bun right now): avoid it for sensitive
   traffic on untrusted networks, or route through a patched client or proxy.
5. **Re-run** `probe_clients.sh` and `scan_bundles.py`. Confirm that the
   control host still works for everything, which proves nothing was broken.

<a name="macos"></a>
## macOS

- **System and browsers**: install macOS updates (Apple's block shipped Oct 19)
  and update browsers. Safari, Chrome, Firefox and apps using the Security
  framework (URLSession, `truststore`, Go) follow Apple's block.
- **`/etc/ssl/cert.pem`** is used by Apple's `curl`, `git`, `python3`, `perl`,
  `ruby` and LibreSSL `openssl`, none of which check revocation. Apple has not
  updated it. Fix it with `scripts/fix_macos_system_bundle.sh`:
  - run `--dry-run` first (no root needed)
  - apply with `sudo bash scripts/fix_macos_system_bundle.sh`
  - **sudo needs a TTY.** Claude Code's Bash tool and `!` commands have none, so
    `sudo` fails with "a terminal is required". Either ask the user to run it
    in their own terminal, or, after the user agrees, open the standard macOS
    admin password dialog:
    `osascript -e 'do shell script "bash /ABS/PATH/fix_macos_system_bundle.sh" with administrator privileges'`
  - The script also sets `PIP_CERT` for Apple's pip (Python 3.9 / pip 21, which
    uses a vendored certifi).
  - **Trade-off**: removing *AAA Certificate Services* can break the
    occasional legitimate site that still chains to that old Sectigo root,
    when accessed with these Apple tools. Tell the user, and give them
    `--restore`.
- **Homebrew**: `brew update && brew upgrade ca-certificates` fixes brew OpenSSL
  (both `openssl@3` and `openssl@4`) and everything linked to it. Upgrade
  `node`, `uv`, `go`, `python@3.x`, `awscli` and `bun` as needed. `brew upgrade X`
  also upgrades X's dependents, so say so in the report. `brew` itself runs on a
  vendored portable Ruby with its own `cert.pem`. `brew update` /
  `brew vendor-install ruby` refreshes it once Homebrew ships a new one.
- **MacPorts**: `sudo port selfupdate && sudo port upgrade curl-ca-bundle certsync`.

<a name="linux"></a>
## Linux

First choice: update `ca-certificates` from the distro (see
patched-versions.md), e.g.
`sudo apt update && sudo apt install --only-upgrade ca-certificates`,
`sudo dnf upgrade ca-certificates`, `sudo pacman -Syu ca-certificates-mozilla`,
`sudo apk upgrade ca-certificates`.

If the distro has not shipped a fix yet, use the advisory's manual distrust (as root):

**Debian / Ubuntu**
```sh
sed -i \
  -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \
  -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \
  /etc/ca-certificates.conf && update-ca-certificates
```

**Alpine**
```sh
apk add ca-certificates &&
sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \
  /etc/ca-certificates.conf && update-ca-certificates
```

**Fedora, RHEL, CentOS Stream, Rocky, AlmaLinux, Amazon Linux 2023**
```sh
d=/etc/pki/ca-trust/source/blocklist; [ -d $d ] || d=/etc/pki/ca-trust/source/blacklist
trust extract --overwrite --format=pem-bundle \
  --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' \
  $d/Comodo_AAA_Services_root.pem &&
trust extract --overwrite --format=pem-bundle \
  --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \
  $d/emSign_ECC_Root_CA_-_G3.pem &&
update-ca-trust
```

**openSUSE / SLES**
```sh
d=/etc/pki/trust/blocklist; [ -d $d ] || d=/etc/pki/trust/blacklist
trust extract --format=pem-bundle \
  --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' \
  $d/Comodo_AAA_Services_root.pem &&
trust extract --format=pem-bundle \
  --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \
  $d/emSign_ECC_Root_CA_-_G3.pem &&
update-ca-certificates
```

**Arch**
```sh
trust extract --format=pem-bundle \
  --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \
  /etc/ca-certificates/trust-source/blocklist/emSign_ECC_Root_CA_-_G3.pem &&
update-ca-trust
```

**NixOS** (`configuration.nix`, then `nixos-rebuild switch`)
```nix
security.pki.caCertificateBlacklist = [
  "Comodo AAA Services root"
  "emSign ECC Root CA - G3"
];
```

Undo: Debian/Ubuntu/Alpine, remove the leading `!` and re-run
`update-ca-certificates`. Fedora/SUSE/Arch, delete the files written to the
blocklist directory and re-run `update-ca-trust` / `update-ca-certificates`.

Snap/Flatpak apps carry their own runtimes and update through
`snap refresh` / `flatpak update`.

<a name="bsd"></a>
## BSD

**NetBSD 10+**
```sh
certctl untrust /usr/share/certs/mozilla/all/emSign_ECC_Root_CA_-_G3.pem &&
certctl untrust /usr/share/certs/mozilla/all/Comodo_AAA_Services_root.pem
```

**FreeBSD 14+** (`ca_root_nss` fix pending)
```sh
cp /etc/ssl/certs/14bc7599.0 /usr/share/certs/untrusted/14bc7599.pem
cp /etc/ssl/certs/ee64a828.0 /usr/share/certs/untrusted/ee64a828.pem
certctl rehash
```
Before copying, check that those hash files really are the two roots:
`openssl x509 -noout -subject -in /etc/ssl/certs/14bc7599.0`.

<a name="windows"></a>
## Windows

- Run Windows Update. Microsoft's block shipped Oct 20 and covers SChannel
  clients (Edge, .NET, PowerShell, `curl.exe` from System32, Go).
- Microsoft's store still lists *emSign Root TLS CA - G3* and *emSign Root CS
  CA - G3* as direct issuers, so the block (not a root removal) is what
  protects Windows. Make sure updates are not deferred.
- Git for Windows ships its own `ca-bundle.crt` unless `http.sslBackend=schannel`
  is set. Update Git for Windows, or switch to schannel.
- Node, Python/certifi, Rust, Bun, Electron, Composer: same versions as on
  other OSes. WSL distros follow the Linux section.
- Code signing: two of the compromised intermediates are **code-signing** CAs.
  On Windows, treat software signed through them as untrusted until Microsoft's
  block is applied.

<a name="embedded"></a>
## Embedded bundles found by `scan_bundles.py`

| Found in | Fix |
|---|---|
| `…/site-packages/certifi/cacert.pem` (virtualenv/project) | `pip install -U 'certifi>=2026.10.19'` in that env (or `uv lock --upgrade-package certifi && uv sync`), and bump lockfiles |
| `~/.cache/uv/…/certifi` | `uv cache clean certifi`, so new envs don't reuse the stale wheel |
| `…/pip/_vendor/certifi/cacert.pem` | Upgrade pip in that interpreter (`python -m pip install -U 'pip>=26.2.2'`), and bake it into Docker images. On macOS, recent pip used `truststore` and was safe despite this file. On Linux, pip 25 used this file and was exposed. The probe decides |
| conda envs | `conda update ca-certificates certifi openssl` in each env |
| `botocore/cacert.pem` (AWS CLI v2, boto3) | Upgrade awscli/botocore, or set `AWS_CA_BUNDLE` to a fixed bundle |
| Ruby gem bundles (httpclient, algoliasearch, cocoapods deps...) | Upgrade the gem or its parent tool. These files often lag for months, so if no update exists, tell the user which tool is affected |
| Homebrew `portable-ruby/*/cert.pem` | `brew update`. Older version folders are leftovers and harmless once unused |
| Java `cacerts` | Update the JDK. Or remove the two roots: `keytool -list -cacerts -storepass changeit` to find the aliases, then `keytool -delete -cacerts -storepass changeit -alias <alias>` (needs root for system JDKs) |
| Perl `Mozilla/CA/cacert.pem` | `cpanm Mozilla::CA` (≥ 20261020) |
| Composer `composer/ca-bundle` | `composer update composer/ca-bundle` |
| Elixir `castore` | `mix deps.update castore` |
| Rust `webpki-roots` | `cargo update -p webpki-roots -p rustls-webpki`, then rebuild and redeploy binaries; the roots are compiled in |
| Electron apps | Update the app. Electron ships Chromium's certificate verifier and blocklists, so the bundled Electron version (fixed: 44.9.1 / 43.8.1 / 42.11.16) decides whether the app is protected |

<a name="containers"></a>
## Containers, CI, servers

- Every image carries its own `ca-certificates`. Rebuild with `docker build --pull`
  after the base image publishes a fix, and redeploy. Pinned digests and
  `FROM node:18` / `node:20` (EOL lines) will not get fixes, so move to a
  supported line.
- To test an image: `docker run --rm IMAGE sh -c 'curl -sS https://dv-g3b-emudhra.we-have-a-problem.com/ ; curl -sS https://dv-g3b-aaa-emudhra.we-have-a-problem.com/'`
  (or copy `probe_clients.sh` into the container).
- Run `scan_lockfiles.py` on each repo. Statically linked Rust and Go binaries
  embed their roots and must be rebuilt.
- TLS-inspecting corporate proxies re-sign all traffic. Behind one, the probe
  results describe the proxy's trust store, so the proxy vendor must patch it.

<a name="rollback"></a>
## Rollback

- macOS: `sudo bash scripts/fix_macos_system_bundle.sh --restore`, and remove the
  `PIP_CERT` line from Apple Python's `sitecustomize.py`.
- Linux/BSD: see the undo notes in each section.
- A rollback re-exposes the machine, so only do it to unbreak a specific site,
  and tell the user.
