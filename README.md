# eMudhra CA compromise: check and fix

A [Claude Code](https://claude.com/claude-code) skill, plus standalone scripts,
that finds and fixes software still trusting the **eight compromised eMudhra
intermediate CAs** (October 2026). Their private keys could be recovered from
the public certificates, so anyone can forge HTTPS certificates for any site
against clients that haven't been updated.

Browsers blocked these intermediates within days. **CLIs, language runtimes,
embedded CA bundles, containers and older OS trust stores did not.** On a
typical developer Mac this found Homebrew Node, Bun, Apple's built-in
curl/git/python, Apple's pip, the AWS CLI's own bundle, project virtualenvs
and the uv cache all still trusting the bad chains.

Advisory: <https://emudhra.we-have-a-problem.com/> ·
Mozilla bug [2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) ·
[Google](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)

## Install as a Claude Code skill

```bash
git clone https://github.com/Prem95/eMudhra-CA-check ~/.claude/skills/emudhra-ca-compromise
```

Then ask Claude Code something like *"am I affected by the eMudhra CA
compromise? fix what needs fixing"*. Claude will:

1. refresh the patched-versions list from the advisory
2. **live-probe** every TLS client it finds (curl, wget, git, openssl, Python,
   requests, pip, Node incl. nvm/volta/fnm/asdf/mise, Bun, Deno, Go, Ruby,
   Perl, PHP, Java) against the advisory's two test hosts, plus a control host
3. **fingerprint-scan** CA bundles, trust directories, OpenSSL dirs and Java
   keystores
4. **scan project lockfiles** (certifi, webpki-roots, rustls-webpki, Electron,
   composer/ca-bundle, castore, Mozilla::CA, Node/Go pins, Dockerfiles)
5. propose an ordered fix plan, **ask before changing anything**, apply it,
   and re-verify

## Or run the scripts yourself

All read-only, no dependencies beyond bash and Python 3:

```bash
bash scripts/probe_clients.sh                  # live test; EXPOSED / SAFE / BROKEN / INCONCLUSIVE per client
python3 -I scripts/scan_bundles.py             # which CA files on disk still contain the affected roots
python3 -I scripts/scan_lockfiles.py ~/code    # which project pins need bumping
```

macOS system bundle fix (Apple hasn't shipped one yet):

```bash
bash scripts/fix_macos_system_bundle.sh --dry-run
sudo bash scripts/fix_macos_system_bundle.sh          # backup kept at /etc/ssl/cert.pem.bak
sudo bash scripts/fix_macos_system_bundle.sh --restore
```

Linux, BSD, Windows, container and CI instructions are in
[`references/platforms.md`](references/platforms.md). Fixed versions are in
[`references/patched-versions.md`](references/patched-versions.md).

## Results you might see

| Verdict | Meaning |
|---|---|
| **EXPOSED** | The client connected to a test host, so it trusts a compromised CA |
| **SAFE** | Rejected both test hosts and still reaches the control host |
| **BROKEN** | Rejects the control host too: too many roots removed, or a TLS-inspecting proxy |
| **INCONCLUSIVE** | Network trouble (the test hosts were flaky). Re-run; this is *not* a pass |

## Caveats

- The test hosts belong to the advisory's author. The probe only opens TLS
  connections to them and to the control host (`CONTROL_HOST`, default
  `www.google.com`).
- Removing *AAA Certificate Services* (part of the advisory's macOS and
  Debian/Fedora fixes) can break the occasional legitimate site that still
  chains to that old Sectigo root.
- Version tables are a snapshot from 2026-10-21. Check the advisory for newer
  releases, especially items marked **pending** (Bun, FreeBSD `ca_root_nss`).
- `data/roots.json` and `data/impacted-intermediates.json` are copied from the
  advisory site ([source](https://github.com/galadran/we-have-a-problem.com)).
- Tested on macOS 26 (bash 3.2, Homebrew) and Debian 13 (`python:3.12-slim`).
