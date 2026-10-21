#!/usr/bin/env python3
"""Offline scan: find CA bundles and trust stores on this machine and report which
still contain the roots or intermediates affected by the October 2026 eMudhra
intermediate CA compromise (matched by SHA-256 fingerprint, not by name).

Read-only, stdlib only. Usage:
    python3 -I scan_bundles.py [--paths FILE_OR_DIR ...] [--no-walk] [--budget SECONDS] [--json]

Exit codes: 0 = no exposed bundle found, 1 = at least one exposed bundle, 2 = error.
"""
import argparse
import base64
import glob
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
PEM_RE = re.compile(
    rb"-----BEGIN (?:TRUSTED )?CERTIFICATE-----(.+?)-----END (?:TRUSTED )?CERTIFICATE-----", re.S
)
IS_MAC = platform.system() == "Darwin"
HOME = Path.home()

# Well-known bundle locations across OSes and package managers.
FIXED_FILES = [
    "/etc/ssl/cert.pem",                                   # macOS (LibreSSL), Alpine, Arch, OpenBSD
    "/etc/ssl/certs/ca-certificates.crt",                  # Debian/Ubuntu/Alpine/Gentoo/Arch
    "/etc/pki/tls/certs/ca-bundle.crt",                    # Fedora/RHEL family
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",   # Fedora/RHEL family
    "/etc/ssl/ca-bundle.pem",                              # openSUSE/SLES
    "/var/lib/ca-certificates/ca-bundle.pem",              # openSUSE/SLES
    "/usr/local/etc/ssl/cert.pem",                         # FreeBSD (ca_root_nss)
    "/usr/local/share/certs/ca-root-nss.crt",              # FreeBSD (ca_root_nss)
    "/etc/openssl/certs/ca-certificates.crt",              # NetBSD
    "/opt/homebrew/etc/ca-certificates/cert.pem",          # Homebrew (Apple silicon)
    "/usr/local/etc/ca-certificates/cert.pem",             # Homebrew (Intel)
    "/home/linuxbrew/.linuxbrew/etc/ca-certificates/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
    "/opt/local/etc/openssl/cert.pem",                     # MacPorts
    "/opt/local/share/curl/curl-ca-bundle.crt",            # MacPorts
    "/usr/share/ca-certificates/trust-source/tls-ca-bundle.pem",
]
# Hashed / one-cert-per-file directories (system trust as OpenSSL sees it).
STORE_DIRS = ["/etc/ssl/certs", "/etc/openssl/certs", "/usr/share/certs/trusted", "/etc/pki/tls/certs"]
# Distrust directories: finding an affected cert HERE is good (it is blocked).
BLOCK_DIRS = [
    "/etc/pki/ca-trust/source/blocklist", "/etc/pki/ca-trust/source/blacklist",
    "/etc/pki/trust/blocklist", "/etc/pki/trust/blacklist",
    "/etc/ca-certificates/trust-source/blocklist", "/etc/ca-certificates/trust-source/blacklist",
    "/usr/share/certs/untrusted", "/etc/openssl/untrusted",
]
ENV_VARS = ["SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS", "PIP_CERT", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE", "HTTPLIB2_CA_CERTS"]
BUNDLE_NAMES = {"cacert.pem", "cacerts.pem", "ca-bundle.crt", "ca-certificates.crt", "cert.pem",
                "ca-bundle.pem", "tls-ca-bundle.pem", "ca-root-nss.crt", "curl-ca-bundle.crt",
                "roots.pem", "ca-bundle.trust.crt"}
PRUNE = {".git", ".hg", ".svn", ".Trash", "proc", "sys", "dev", "__pycache__", ".cache-loader"}
# Top-level home folders that trigger macOS privacy (TCC) prompts when walked.
MAC_TCC_HOME = {"Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Library",
                "Applications", "Public", "Mobile Documents"}


def load_targets():
    targets = {}
    for r in json.loads((DATA / "roots.json").read_text()):
        targets[r["sha256"].upper()] = {
            "kind": "root", "name": r["name"], "role": r.get("role", ""),
            "store_status": r.get("root_store_status", {}),
        }
    for i in json.loads((DATA / "impacted-intermediates.json").read_text()):
        targets[i["sha256"].upper()] = {
            "kind": "intermediate", "name": f'{i["name"]} (issued by {i["issued_by"]})',
            "role": i.get("usage", ""),
        }
    return targets


def der_slice(der):
    """Trim OpenSSL 'TRUSTED CERTIFICATE' aux data: keep only the outer DER SEQUENCE."""
    if len(der) < 4 or der[0] != 0x30:
        return der
    n = der[1]
    if n < 0x80:
        return der[: 2 + n]
    nbytes = n & 0x7F
    length = int.from_bytes(der[2: 2 + nbytes], "big")
    return der[: 2 + nbytes + length]


def fingerprints_in(path):
    try:
        if os.path.getsize(path) > 8 * 1024 * 1024:
            return []
        data = Path(path).read_bytes()
    except (OSError, ValueError):
        return []
    fps = []
    for m in PEM_RE.finditer(data):
        try:
            der = base64.b64decode(b"".join(m.group(1).split()), validate=False)
        except Exception:
            continue
        fps.append(hashlib.sha256(der_slice(der)).hexdigest().upper())
    if not fps and data[:1] == b"\x30":  # single DER-encoded cert file
        fps.append(hashlib.sha256(der_slice(data)).hexdigest().upper())
    return fps


def label_for(path):
    p = str(path)
    parts = set(Path(p).parts)
    if "/ca-certificates/" in p and ("homebrew" in p.lower() or "/usr/local/" in p or "linuxbrew" in p):
        if "/Cellar/" in p or "/.cellar/" in p:
            return "Homebrew ca-certificates keg (installed copy; the live one is etc/ca-certificates/cert.pem)"
        return "Homebrew ca-certificates (brew OpenSSL, python@3.x, curl, wget, ...)"
    if "openssl@3" in p:
        return "Homebrew OpenSSL default bundle"
    if "_vendor" in parts and "certifi" in parts:
        return "pip's vendored certifi (used by pip unless it picks truststore; probe pip to confirm)"
    if "certifi" in parts:
        where = ""
        if "/.cache/uv/" in p or "/uv/archive" in p:
            where = " — uv cache: new venvs will reuse it until cleaned"
        elif "/.venv/" in p or "/venv/" in p or "/virtualenvs/" in p:
            where = " — project virtualenv"
        return "Python certifi (requests, httpx, aiohttp, ...)" + where
    if "botocore" in parts:
        return "botocore/AWS CLI own bundle (awscli ignores system roots by default)"
    if "portable-ruby" in parts:
        return "Homebrew's own portable Ruby (used by `brew` itself)"
    if "gems" in parts:
        return "Ruby gem bundled CA file (that gem's HTTP client)"
    if "Mozilla" in parts and "CA" in parts or "Mozilla-CA" in p:
        return "Perl Mozilla::CA"
    if "composer" in p and "ca-bundle" in p:
        return "PHP composer/ca-bundle"
    if "castore" in parts:
        return "Elixir castore"
    if "webpki" in p:
        return "Rust webpki roots"
    if p == "/etc/ssl/cert.pem" and IS_MAC:
        return "macOS /etc/ssl/cert.pem (built-in curl, git, python3, perl, ruby, openssl)"
    if p.startswith(("/etc/", "/var/lib/ca-certificates", "/usr/local/etc/ssl", "/usr/local/share/certs",
                     "/usr/share/ca-certificates")):
        return "system trust bundle (OpenSSL/GnuTLS consumers)"
    if "conda" in p or "anaconda" in p or "miniforge" in p:
        return "conda environment bundle"
    if "node_modules" in p:
        return "npm package bundle"
    return "CA bundle"


def walk(roots, budget, deadline_state):
    found = set()
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if time.monotonic() > deadline_state["deadline"]:
                deadline_state["truncated"] = True
                return found
            dp = Path(dirpath)
            depth = len(dp.parts) - base_depth
            keep = []
            for d in dirnames:
                if d in PRUNE or d.endswith((".photoslibrary", ".app", ".musiclibrary")):
                    continue
                if IS_MAC and dp == HOME and d in MAC_TCC_HOME:
                    continue
                keep.append(d)
            dirnames[:] = keep if depth < 14 else []
            for f in filenames:
                if f in BUNDLE_NAMES:
                    found.add(str(dp / f))
    return found


def java_keystores():
    """Yield (label, [fingerprints]) for each JDK cacerts keystore found."""
    homes = set()
    if os.environ.get("JAVA_HOME"):
        homes.add(os.environ["JAVA_HOME"])
    if IS_MAC:
        jh = "/usr/libexec/java_home"
        if os.path.exists(jh):
            try:
                out = subprocess.run([jh, "-V"], capture_output=True, text=True, timeout=20)
                for line in (out.stdout + out.stderr).splitlines():
                    m = re.search(r"(/\S.*?/Contents/Home)\s*$", line.strip())
                    if m:
                        homes.add(m.group(1))
            except Exception:
                pass
    homes.update(glob.glob("/usr/lib/jvm/*"))
    homes.update(glob.glob(str(HOME / ".sdkman/candidates/java/*")))
    seen = set()
    for h in sorted(homes):
        kt = Path(h) / "bin" / "keytool"
        if not kt.exists():
            continue
        real = os.path.realpath(h)
        if real in seen:
            continue
        seen.add(real)
        try:
            out = subprocess.run([str(kt), "-list", "-cacerts", "-storepass", "changeit", "-v"],
                                 capture_output=True, text=True, timeout=60)
        except Exception:
            continue
        fps = [m.replace(":", "").upper()
               for m in re.findall(r"SHA256:\s*([0-9A-Fa-f:]{95})", out.stdout)]
        yield f"Java cacerts ({h})", fps


def openssl_dirs():
    """Ask every openssl binary for its OPENSSLDIR (paths move between major
    versions, e.g. Homebrew's openssl@4 uses etc/openssl@4)."""
    bins = set()
    for d in os.environ.get("PATH", "").split(os.pathsep):
        b = os.path.join(d, "openssl")
        if os.access(b, os.X_OK):
            bins.add(os.path.realpath(b))
    bins.update(os.path.realpath(b) for b in glob.glob("/opt/homebrew/opt/openssl*/bin/openssl")
                + glob.glob("/usr/local/opt/openssl*/bin/openssl"))
    dirs = set()
    for b in bins:
        try:
            out = subprocess.run([b, "version", "-d"], capture_output=True, text=True, timeout=10).stdout
        except Exception:
            continue
        m = re.search(r'OPENSSLDIR: "([^"]+)"', out)
        if m and os.path.isdir(m.group(1)):
            dirs.add(m.group(1))
    return sorted(dirs)


def mac_system_roots():
    """Informational: is an affected root in Apple's system root keychain?"""
    kc = "/System/Library/Keychains/SystemRootCertificates.keychain"
    if not (IS_MAC and os.path.exists(kc)):
        return []
    try:
        out = subprocess.run(["security", "find-certificate", "-a", "-Z", kc],
                             capture_output=True, text=True, timeout=60).stdout
    except Exception:
        return []
    return re.findall(r"SHA-256 hash:\s*([0-9A-F]{64})", out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--paths", nargs="*", default=[], help="extra files or directories to scan")
    ap.add_argument("--no-walk", action="store_true", help="only check well-known locations")
    ap.add_argument("--budget", type=float, default=90, help="time budget for the filesystem walk (s)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    try:
        targets = load_targets()
    except Exception as e:
        print(f"cannot load fingerprint data from {DATA}: {e}", file=sys.stderr)
        return 2

    files = {}  # realpath -> (display path, note)
    def add(p, note=""):
        if p and os.path.isfile(p):
            files.setdefault(os.path.realpath(p), (p, note))

    for p in FIXED_FILES:
        add(p)
    store_dirs = list(STORE_DIRS)
    for d in openssl_dirs():
        add(os.path.join(d, "cert.pem"), f"default bundle of OpenSSL with OPENSSLDIR {d}")
        store_dirs.append(os.path.join(d, "certs"))
    for v in ENV_VARS:
        val = os.environ.get(v)
        if val and os.path.isfile(val):
            add(val, f"referenced by ${v}" + (" (adds to, does not replace, Node's roots)" if v == "NODE_EXTRA_CA_CERTS" else ""))
        elif val and os.path.isdir(val):
            args.paths.append(val)

    state = {"deadline": time.monotonic() + args.budget, "truncated": False}
    walk_roots = [str(HOME), "/opt", "/usr/local", "/usr/lib", "/usr/lib64", "/usr/share",
                  "/Library/Developer/CommandLineTools", "/Library/Python", "/Library/Frameworks/Python.framework",
                  str(HOME / "Library/Python"), str(HOME / "Library/Application Support/pypoetry")]
    extra_dirs = []
    for p in args.paths:
        if os.path.isdir(p):
            extra_dirs.append(p)
        else:
            add(p, "requested")
    for p in walk(extra_dirs, args.budget, state):
        add(p)
    if not args.no_walk:
        for p in walk(walk_roots, args.budget, state):
            add(p)

    results = []
    for real, (shown, note) in sorted(files.items(), key=lambda kv: kv[1][0]):
        hits = [targets[f] for f in fingerprints_in(real) if f in targets]
        results.append({"path": shown, "realpath": real, "label": label_for(shown), "note": note,
                        "status": "EXPOSED" if hits else "clean",
                        "affected": sorted({h["name"] for h in hits})})

    for d in dict.fromkeys(store_dirs):
        if not os.path.isdir(d) or not os.listdir(d):
            continue
        hits = set()
        for f in os.listdir(d):
            fp = os.path.join(d, f)
            if os.path.isfile(fp) and os.path.realpath(fp) not in files and not f.endswith((".crt.bak",)):
                for x in fingerprints_in(fp):
                    if x in targets:
                        hits.add(targets[x]["name"])
        results.append({"path": d + "/", "realpath": d, "label": "hashed system trust directory",
                        "note": "", "status": "EXPOSED" if hits else "clean", "affected": sorted(hits)})

    blocked = []
    for d in BLOCK_DIRS:
        if os.path.isdir(d):
            for f in os.listdir(d):
                for x in fingerprints_in(os.path.join(d, f)):
                    if x in targets:
                        blocked.append({"path": os.path.join(d, f), "name": targets[x]["name"]})

    for label, fps in java_keystores():
        hits = sorted({targets[f]["name"] for f in fps if f in targets})
        results.append({"path": label, "realpath": label, "label": "Java TLS (JSSE) trust store",
                        "note": "", "status": "EXPOSED" if hits else "clean", "affected": hits})

    apple = sorted({targets[f]["name"] for f in mac_system_roots() if f in targets})

    exposed = [r for r in results if r["status"] == "EXPOSED"]
    out = {"exposed_count": len(exposed), "scanned_count": len(results), "results": results,
           "blocklisted": blocked, "apple_system_roots_present": apple,
           "walk_truncated": state["truncated"]}

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"Scanned {len(results)} bundles/stores"
              + (" (filesystem walk hit the time budget; pass --budget to extend)" if state["truncated"] else ""))
        print()
        for r in sorted(results, key=lambda r: (r["status"] != "EXPOSED", r["path"])):
            mark = "EXPOSED" if r["status"] == "EXPOSED" else "clean  "
            print(f"[{mark}] {r['path']}")
            print(f"           {r['label']}{(' — ' + r['note']) if r['note'] else ''}")
            for a in r["affected"]:
                print(f"           contains: {a}")
        if blocked:
            print("\nBlocklisted (good — these are explicitly distrusted):")
            for b in blocked:
                print(f"  {b['path']}: {b['name']}")
        if apple:
            print("\nmacOS system root keychain contains: " + ", ".join(apple)
                  + "\n  (informational: Apple blocks the compromised intermediates separately; keep macOS updated)")
        print(f"\nSummary: {len(exposed)} exposed of {len(results)} scanned.")
    return 1 if exposed else 0


if __name__ == "__main__":
    sys.exit(main())
