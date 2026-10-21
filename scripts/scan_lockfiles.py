#!/usr/bin/env python3
"""Scan project lockfiles and version pins for dependencies that embed their own
root store and need the October 2026 eMudhra fix (certifi, webpki-roots,
rustls-webpki, Electron, composer/ca-bundle, castore, Mozilla::CA, pip) plus
pinned Node/Go/Bun runtime versions (.nvmrc, .node-version, .tool-versions,
Dockerfile FROM lines, go.mod toolchain).

Read-only, stdlib only. Usage:
    python3 -I scan_lockfiles.py [DIR ...] [--json]
Exit codes: 0 = nothing outdated, 1 = something needs updating, 2 = error.

The minimum versions below are a snapshot of the advisory's table taken on
2026-10-21; check https://emudhra.we-have-a-problem.com/ for newer releases.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

SNAPSHOT_DATE = "2026-10-21"

# name -> rule. "min": single minimum. "series": {major-or-minor-prefix: minimum};
# a release line not listed is treated as unpatched. "pending": no fix yet.
RULES = {
    "certifi":            {"min": "2026.10.19", "eco": "Python"},
    "pip":                {"min": "26.2.2", "eco": "Python"},
    "webpki-roots":       {"min": "1.0.10", "eco": "Rust", "shim": "0.26"},
    "webpki-root-certs":  {"min": "1.0.10", "eco": "Rust"},
    "rustls-webpki":      {"series": {"0.103": "0.103.16"}, "eco": "Rust"},
    "electron":           {"series": {"44": "44.9.1", "43": "43.8.1", "42": "42.11.16"}, "eco": "Electron"},
    "composer/ca-bundle": {"series": {"1.4": "1.4.16", "1.5": "1.6.0", "1.6": "1.6.0"}, "eco": "PHP"},
    "castore":            {"min": "1.0.22", "eco": "Elixir"},
    "Mozilla-CA":         {"min": "20261020", "eco": "Perl"},
    "node":               {"series": {"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"}, "eco": "runtime"},
    "go":                 {"series": {"1.26": "1.26.10", "1.27": "1.27.3"}, "eco": "runtime"},
    "bun":                {"pending": True, "eco": "runtime"},
}
PRUNE = {".git", "node_modules", "target", ".venv", "venv", "vendor", "dist", "build", "deps",
         "_build", ".next", ".tox", "__pycache__", ".terraform", "Pods"}


def vt(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def judge(name, version):
    """Return (status, detail). status: ok | outdated | unpatched-line | pending | unknown."""
    rule = RULES[name]
    v = version.strip().lstrip("v=^~")
    if rule.get("pending"):
        return "pending", "no fixed release published yet; see mitigation in references/patched-versions.md"
    if not re.match(r"\d", v):
        return "unknown", f"unpinned or non-numeric version '{version}'"
    if "shim" in rule and v.startswith(rule["shim"] + "."):
        return "ok", f"{rule['shim']}.x is a compat shim over webpki-roots 1.x; check the 1.x entry"
    if "min" in rule:
        return ("ok", "") if vt(v) >= vt(rule["min"]) else ("outdated", f"needs >= {rule['min']}")
    nums = re.findall(r"\d+", v)
    for prefix, minimum in rule["series"].items():
        plen = prefix.count(".") + 1
        if ".".join(nums[:plen]) == prefix:
            return ("ok", "") if vt(v) >= vt(minimum) else ("outdated", f"needs >= {minimum}")
    newest = max(rule["series"].values(), key=vt)
    if vt(v) > vt(newest):
        return "unknown", f"newer than any line in the {SNAPSHOT_DATE} table; verify with the advisory"
    return "unpatched-line", f"release line has no fix; move to a supported line (e.g. {newest})"


def judge_floating(name, tag):
    """Docker tags like node:22-slim or golang:1.27 track a release line."""
    m = re.match(r"\d+(?:\.\d+)?", tag)
    line = m.group(0) if m else ""
    series = RULES[name].get("series", {})
    if line and line not in series and series and vt(line) < min(vt(k) for k in series):
        return "unpatched-line", f"tag '{tag}' tracks an end-of-life line with no fix", tag
    return "unknown", f"floating tag '{tag}': pull and rebuild (docker build --pull) to pick up the fix", tag


def toml_packages(text):
    # Cargo.lock, uv.lock, poetry.lock, pdm.lock share [[package]] name/version blocks.
    for m in re.finditer(r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text):
        yield m.group(1), m.group(2)


def parse(path):
    name = path.name
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return
    if name in ("Cargo.lock", "uv.lock", "poetry.lock", "pdm.lock"):
        for n, v in toml_packages(text):
            n = n.lower()
            if n in RULES:
                yield n, v
    elif name == "Pipfile.lock":
        try:
            data = json.loads(text)
        except ValueError:
            return
        for section in ("default", "develop"):
            for n, meta in (data.get(section) or {}).items():
                if n.lower() in RULES and isinstance(meta, dict) and meta.get("version"):
                    yield n.lower(), meta["version"]
    elif re.match(r"(requirements.*|constraints.*)\.(txt|in)$", name):
        for m in re.finditer(r"^\s*(certifi|pip)\s*==\s*([\w.]+)", text, re.M | re.I):
            yield m.group(1).lower(), m.group(2)
    elif name == "package-lock.json":
        try:
            data = json.loads(text)
        except ValueError:
            return
        pk = (data.get("packages") or {}).get("node_modules/electron") or (data.get("dependencies") or {}).get("electron")
        if isinstance(pk, dict) and pk.get("version"):
            yield "electron", pk["version"]
    elif name in ("yarn.lock", "pnpm-lock.yaml", "bun.lock"):
        found = set(re.findall(r'(?:^|["/\s])electron@(?:npm:)?(\d+\.\d+\.\d+)', text, re.M))
        found |= set(re.findall(r'^"?electron@[^\n]*:\n\s+version:? "?(\d+\.\d+\.\d+)', text, re.M))
        for v in sorted(found, key=vt):
            yield "electron", v
    elif name == "composer.lock":
        try:
            data = json.loads(text)
        except ValueError:
            return
        for p in (data.get("packages") or []) + (data.get("packages-dev") or []):
            if p.get("name") == "composer/ca-bundle":
                yield "composer/ca-bundle", p.get("version", "")
    elif name == "mix.lock":
        m = re.search(r'"castore":\s*\{:hex,\s*:castore,\s*"([^"]+)"', text)
        if m:
            yield "castore", m.group(1)
    elif name == "cpanfile.snapshot":
        for v in re.findall(r"^\s*Mozilla-CA-(\d+)\s*$", text, re.M):
            yield "Mozilla-CA", v
    elif name in (".nvmrc", ".node-version"):
        v = text.strip().splitlines()[0] if text.strip() else ""
        if re.match(r"v?\d+\.\d+\.\d+", v):
            yield "node", v
    elif name == ".tool-versions":
        for tool, v in re.findall(r"^(nodejs|golang|bun)\s+(\S+)", text, re.M):
            yield {"nodejs": "node", "golang": "go", "bun": "bun"}[tool], v
    elif name == "go.mod":
        m = re.search(r"^toolchain\s+go(\d+\.\d+\.\d+)", text, re.M)
        if m:
            yield "go", m.group(1)
    elif name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        for img, tag in re.findall(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?:docker\.io/)?(?:library/)?(node|golang|oven/bun):(\S+)", text, re.M | re.I):
            v = re.match(r"\d+(?:\.\d+){0,2}", tag)
            if v and v.group(0).count(".") == 2:
                yield {"node": "node", "golang": "go", "oven/bun": "bun"}[img.lower()], v.group(0)
            elif img.lower() != "oven/bun":
                yield {"node": "node", "golang": "go"}[img.lower()], "floating:" + tag


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dirs", nargs="*", default=["."])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rows = []
    for root in args.dirs:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in PRUNE and not d.startswith(".") or d in (".github",)]
            for f in filenames:
                p = Path(dirpath) / f
                for n, v in parse(p) or ():
                    if v.startswith("floating:"):
                        status, detail, v = judge_floating(n, v[len("floating:"):])
                    else:
                        status, detail = judge(n, v)
                    rows.append({"file": str(p), "package": n, "version": v, "status": status,
                                 "detail": detail, "ecosystem": RULES[n]["eco"]})

    bad = [r for r in rows if r["status"] in ("outdated", "unpatched-line", "pending")]
    if args.json:
        print(json.dumps({"snapshot_date": SNAPSHOT_DATE, "needs_action": len(bad), "results": rows}, indent=2))
    else:
        if not rows:
            print("No relevant lockfiles or version pins found.")
        order = {"outdated": 0, "unpatched-line": 1, "pending": 2, "unknown": 3, "ok": 4}
        for r in sorted(rows, key=lambda r: (order[r["status"]], r["file"])):
            print(f"[{r['status']:<14}] {r['package']:<18} {r['version']:<14} {r['file']}"
                  + (f"\n                 {r['detail']}" if r["detail"] else ""))
        print(f"\nSummary: {len(bad)} need action of {len(rows)} pins found (version table snapshot {SNAPSHOT_DATE}).")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
