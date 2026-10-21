#!/bin/bash
# macOS workaround from https://emudhra.we-have-a-problem.com/ (macOS section):
#   1. remove "AAA Certificate Services" and "emSign ECC Root CA - G3" from
#      /etc/ssl/cert.pem (used by Apple's curl, git, python3, perl, ruby, openssl,
#      none of which check revocation), keeping a backup at /etc/ssl/cert.pem.bak
#   2. point Apple's built-in pip (Command Line Tools python3) at that file
#
# Usage:
#   bash fix_macos_system_bundle.sh --dry-run     # no root needed; shows what would change
#   sudo bash fix_macos_system_bundle.sh          # apply (idempotent)
#   sudo bash fix_macos_system_bundle.sh --restore
#
# Needs a real terminal for sudo. From an agent without a TTY, run it through the
# macOS admin dialog instead:
#   osascript -e 'do shell script "bash /path/to/fix_macos_system_bundle.sh" with administrator privileges'
set -euo pipefail

PEM=/etc/ssl/cert.pem
BAK=/etc/ssl/cert.pem.bak
MODE="${1:-apply}"

[ "$(uname -s)" = Darwin ] || { echo "macOS only" >&2; exit 2; }

filter() {
  awk '/^(###|===) /{skip=0}
    /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1}
    !skip' "$1"
}
count() { grep -c 'BEGIN CERTIFICATE' "$1" || true; }

case "$MODE" in
  --restore)
    [ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
    [ -f "$BAK" ] || { echo "no backup at $BAK" >&2; exit 1; }
    cp -p "$BAK" "$PEM" && echo "restored $PEM from $BAK ($(count "$PEM") certificates)"
    exit 0 ;;
  --dry-run|apply) ;;
  *) echo "usage: $0 [--dry-run|--restore]" >&2; exit 2 ;;
esac

SRC="$PEM"; [ -f "$BAK" ] && SRC="$BAK"   # always filter from the pristine copy
matches="$(grep -cE '^=== .*/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$' "$SRC" || true)"
if ! grep -q '^=== /' "$SRC"; then
  echo "$SRC is not in Apple's annotated format (no '=== /subject' headers); refusing to edit." >&2
  echo "Remove the two roots by hand, or check whether a macOS update already changed this file." >&2
  exit 3
fi

TMPF="$(mktemp "${TMPDIR:-/tmp}/cert.pem.XXXXXX")"; trap 'rm -f "$TMPF"' EXIT
filter "$SRC" > "$TMPF"
before="$(count "$SRC")"; after="$(count "$TMPF")"; removed=$((before - after))
echo "source: $SRC  ($before certificates, $matches matching entries)"
echo "result: $after certificates (removes $removed)"
if [ "$removed" -ne "$matches" ] || [ "$removed" -gt 2 ]; then
  echo "unexpected removal count; refusing to continue" >&2; exit 3
fi
if [ "$matches" = 0 ] && cmp -s "$SRC" "$PEM"; then
  echo "nothing to remove: $PEM no longer contains the affected roots"
fi

F=""   # /usr/bin/python3 pops up an installer when Command Line Tools are missing
if xcode-select -p >/dev/null 2>&1; then
  F="$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' 2>/dev/null)/sitecustomize.py" || F=""
fi

if [ "$MODE" = --dry-run ]; then
  cmp -s "$TMPF" "$PEM" && echo "dry run: $PEM is already filtered" || echo "dry run: would rewrite $PEM (backup: $BAK)"
  if [ -n "$F" ]; then
    grep -qs PIP_CERT "$F" && echo "dry run: pip already configured in $F" || echo "dry run: would add PIP_CERT to $F"
  fi
  exit 0
fi

[ "$(id -u)" = 0 ] || { echo "run with sudo (or see the osascript note at the top)" >&2; exit 1; }
[ -f "$BAK" ] || cp -p "$PEM" "$BAK"
if ! cmp -s "$TMPF" "$PEM"; then
  install -m 644 -o root -g wheel "$TMPF" "$PEM"
  echo "rewrote $PEM ($after certificates); backup at $BAK"
else
  echo "$PEM already filtered"
fi

if [ -n "$F" ] && [ -d "$(dirname "$F")" ]; then
  grep -qs PIP_CERT "$F" || echo 'import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")' >> "$F"
  chmod 644 "$F"
  echo "pip: PIP_CERT set in $F"
else
  echo "pip: Apple python3 not installed (Command Line Tools absent); skipped"
fi
