#!/usr/bin/env bash
# Live test: point every TLS client found on this machine at the advisory's two
# test hosts (served with certificates chaining through compromised eMudhra
# intermediates) plus a known-good control host.
#
#   CONNECTED to a test host -> that client still trusts the compromised CAs (EXPOSED)
#   REJECTED  (cert error)   -> good
#   NETERR    (timeout, DNS, refused) -> inconclusive; retried automatically
#   control REJECTED         -> client is BROKEN (over-removed roots, or a TLS-inspecting proxy)
#
# Read-only. Contacts *.we-have-a-problem.com and $CONTROL_HOST only.
# Usage: probe_clients.sh [kind ...]   kinds: curl wget git openssl python requests pip
#                                            node bun deno ruby perl php go java
# Env:   CONTROL_HOST (default www.google.com)  PROBE_TIMEOUT (15)  PROBE_RETRIES (3)
# Exit:  0 nothing exposed, 1 something exposed, 3 only inconclusive/broken results.
# Works with macOS bash 3.2.

set -u
IFS=$'\n'   # paths may contain spaces (e.g. "Application Support")
H1=dv-g3b-emudhra.we-have-a-problem.com
H2=dv-g3b-aaa-emudhra.we-have-a-problem.com
CONTROL="${CONTROL_HOST:-www.google.com}"
TO="${PROBE_TIMEOUT:-15}"
RETRIES="${PROBE_RETRIES:-3}"
KINDS="${*:-curl wget git openssl python requests pip node bun deno ruby perl php go java}"
OS="$(uname -s)"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/emudhra-probe.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT
cd "$TMP" || exit 2   # never run interpreters from a directory with planted modules

HARD_TO=$((TO + 10))
if command -v timeout >/dev/null 2>&1; then
  hard() { timeout "$HARD_TO" "$@"; }
elif command -v gtimeout >/dev/null 2>&1; then
  hard() { gtimeout "$HARD_TO" "$@"; }
elif command -v perl >/dev/null 2>&1; then
  hard() { perl -e 'alarm shift; exec @ARGV or exit 127' "$HARD_TO" "$@"; }
else
  hard() { "$@"; }
fi

rp() { realpath "$1" 2>/dev/null || perl -MCwd=abs_path -e 'print abs_path(shift)' "$1" 2>/dev/null || echo "$1"; }

# On macOS, /usr/bin/{git,python3} are shims that pop up an installer when the
# Command Line Tools are missing. Skip them in that case instead of interrupting.
mac_shim_ok() {
  [ "$OS" != Darwin ] && return 0
  case "$1" in /usr/bin/git|/usr/bin/python3|/usr/bin/pip3) xcode-select -p >/dev/null 2>&1 ;; *) return 0 ;; esac
}

CERT_RE='certificate verify failed|unable to get local issuer|SSL certificate problem|CERTIFICATE_VERIFY_FAILED|UNABLE_TO_GET_ISSUER|UNABLE_TO_VERIFY_LEAF|SELF_SIGNED_CERT|CERT_UNTRUSTED|CERT_REVOKED|CERT_HAS_EXPIRED|invalid peer certificate|UnknownIssuer|x509:|unknown authority|certificate verification failed|cannot verify|issuer certificate|Verify return code: [1-9]|verify error|unknown ca|bad certificate|ERR_TLS_CERT|PKIX path|SunCertPathBuilder|ValidatorException|CertificateException|SSLHandshakeException|certificate is not trusted|CERTIFICATE_REQUIRED|unable to verify|is revoked|certificate revoked|problem confirming the ssl certificate|SecTrust|not trusted'

classify() { # $1 = output file
  if grep -qE "$CERT_RE" "$1"; then echo REJECTED
  elif grep -q 'PROBE_OK' "$1"; then echo CONNECTED
  else echo NETERR; fi
}

# ---- one function per client kind: probe_<kind> BIN HOST > outfile -----------
probe_curl() { hard "$1" -sS -m "$TO" -o /dev/null "https://$2/" 2>&1 && echo PROBE_OK; }
probe_wget() { hard "$1" -q -T "$TO" -t 1 -O /dev/null "https://$2/" 2>&1; rc=$?; [ $rc = 0 ] || [ $rc = 8 ] && echo PROBE_OK; }
probe_git() {
  local o
  o="$(GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false hard "$1" -c credential.helper= -c http.lowSpeedLimit=1 \
        -c http.lowSpeedTime="$TO" ls-remote "https://$2/" 2>&1)"; echo "$o"
  echo "$o" | grep -qE "$CERT_RE" && return
  echo "$o" | grep -qE 'returned error: [0-9]{3}|not found|Authentication failed|not valid|did not send all necessary|HTTP [0-9]{3}|repository' && echo PROBE_OK
}
probe_openssl() {
  local o
  o="$(echo | hard "$1" s_client -connect "$2:443" -servername "$2" -verify_return_error 2>&1)"
  echo "$o" | grep -E 'Verify return code|verify error|errno|connect:' | head -3
  # s_client prints "Verify return code: 0" even when the peer reset before sending a
  # certificate, so also require that a server certificate was actually received.
  echo "$o" | grep -q 'BEGIN CERTIFICATE' && echo "$o" | grep -q 'Verify return code: 0 (ok)' && echo PROBE_OK
}
probe_python() {
  hard "$1" -c 'import sys,urllib.request,urllib.error
try:
    urllib.request.urlopen("https://"+sys.argv[1]+"/", timeout=float(sys.argv[2])); print("PROBE_OK")
except urllib.error.HTTPError: print("PROBE_OK")
except Exception as e: print(repr(e))' "$2" "$TO" 2>&1
}
probe_requests() {
  hard "$1" -c 'import sys
try: import requests
except ImportError: print("NO_REQUESTS"); sys.exit()
try: requests.head("https://"+sys.argv[1]+"/", timeout=float(sys.argv[2])); print("PROBE_OK")
except Exception as e: print(repr(e))' "$2" "$TO" 2>&1
}
probe_pip() {
  # "No matching distribution" also appears after a failed fetch, so look for proof that
  # pip got an HTTP response (verbose log) before calling it connected.
  hard "$1" -m pip download -vvv --no-deps --disable-pip-version-check --no-cache-dir --retries 0 --timeout "$TO" \
    --index-url "https://$2/simple/" -d "$TMP/pip" emudhra-probe-nonexistent > "$TMP/pip.out" 2>&1
  grep -E "$CERT_RE|Could not fetch|connection error|Connection|timed out" "$TMP/pip.out" | head -3
  grep -qE "$CERT_RE" "$TMP/pip.out" && return
  grep -qE "HTTP/1\.[01]\" [0-9]{3}|[0-9]{3} Client Error" "$TMP/pip.out" && echo PROBE_OK
}
JS='const t=+process.env.PROBE_TO*1000;const r=require("https").get("https://"+process.env.PROBE_HOST+"/",{timeout:t},()=>{console.log("PROBE_OK");process.exit(0)});r.on("timeout",()=>{console.log("TIMEOUT");process.exit(3)});r.on("error",e=>{console.log("ERR",e.code,e.message);process.exit(2)});'
probe_node() { PROBE_HOST="$2" PROBE_TO="$TO" hard "$1" -e "$JS" 2>&1; }
probe_bun()  { PROBE_HOST="$2" PROBE_TO="$TO" hard "$1" -e "$JS" 2>&1; }
probe_deno() {
  PROBE_HOST="$2" PROBE_TO="$TO" hard "$1" eval 'try{await fetch("https://"+Deno.env.get("PROBE_HOST")+"/",{signal:AbortSignal.timeout(+Deno.env.get("PROBE_TO")*1000)});console.log("PROBE_OK")}catch(e){console.log("ERR",String(e),String(e.cause??""))}' 2>&1
}
probe_ruby() {
  PROBE_HOST="$2" PROBE_TO="$TO" hard "$1" -rnet/http -e 'begin; t=ENV["PROBE_TO"].to_i; Net::HTTP.start(ENV["PROBE_HOST"],443,use_ssl:true,open_timeout:t,read_timeout:t){|h| h.head("/")}; puts "PROBE_OK"; rescue Exception => e; puts e.class, e.message; end' 2>&1
}
probe_perl() {
  "$1" -MIO::Socket::SSL -e 1 2>/dev/null || { echo NO_IO_SOCKET_SSL; return; }
  PROBE_HOST="$2" PROBE_TO="$TO" hard "$1" -MIO::Socket::SSL -e 'my $h=$ENV{PROBE_HOST}; my $s=IO::Socket::SSL->new(PeerHost=>$h,PeerPort=>443,SSL_hostname=>$h,SSL_verify_mode=>1,Timeout=>$ENV{PROBE_TO}); if($s){print "PROBE_OK\n"}else{print "ERR $IO::Socket::SSL::SSL_ERROR $!\n"}' 2>&1
}
probe_php() {
  PROBE_HOST="$2" hard "$1" -r '$c=stream_context_create(["ssl"=>["verify_peer"=>true,"verify_peer_name"=>true],"http"=>["timeout"=>'"$TO"',"ignore_errors"=>true]]); $r=@file_get_contents("https://".getenv("PROBE_HOST")."/",false,$c); if($r!==false){echo "PROBE_OK\n";}else{$e=error_get_last(); echo "ERR ".($e?$e["message"]:"")."\n";}' 2>&1
}
probe_go() {
  [ -f "$TMP/probe.go" ] || cat > "$TMP/probe.go" <<'EOF'
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	c := &http.Client{Timeout: 20 * time.Second}
	r, err := c.Head("https://" + os.Args[1] + "/")
	if err != nil {
		fmt.Println("ERR", err)
		return
	}
	r.Body.Close()
	fmt.Println("PROBE_OK")
}
EOF
  [ -x "$TMP/probe-go" ] || GOTOOLCHAIN=local GOFLAGS= GO111MODULE=off hard "$1" build -o "$TMP/probe-go" "$TMP/probe.go" >"$TMP/gobuild.log" 2>&1 || { echo "BUILD_FAILED"; cat "$TMP/gobuild.log"; return; }
  hard "$TMP/probe-go" "$2" 2>&1
}
probe_java() {
  [ -f "$TMP/Probe.java" ] || cat > "$TMP/Probe.java" <<'EOF'
public class Probe {
  public static void main(String[] a) throws Exception {
    try {
      var c = (javax.net.ssl.HttpsURLConnection) new java.net.URL("https://" + a[0] + "/").openConnection();
      c.setConnectTimeout(15000); c.setReadTimeout(15000); c.setRequestMethod("HEAD");
      c.getResponseCode(); System.out.println("PROBE_OK");
    } catch (Exception e) { System.out.println("ERR " + e); }
  }
}
EOF
  hard "$1" "$TMP/Probe.java" "$2" 2>&1
}

# ---- discovery ---------------------------------------------------------------
SEEN=""
CANDIDATES="$TMP/candidates"; : > "$CANDIDATES"
add() { # kind path
  [ -n "$2" ] && [ -x "$2" ] || return 0
  mac_shim_ok "$2" || { echo "$1	$2	SKIP (macOS Command Line Tools not installed)" >> "$TMP/skipped"; return 0; }
  local r; r="$(rp "$2")"
  case "$SEEN" in *"|$1:$r|"*) return 0 ;; esac
  SEEN="$SEEN|$1:$r|"
  printf '%s\t%s\n' "$1" "$2" >> "$CANDIDATES"
}
all_in_path() { which -a "$1" 2>/dev/null; }
globs() { for g in "$@"; do for f in $g; do [ -e "$f" ] && echo "$f"; done; done; }

want() { case " $(printf "%s" "$KINDS" | tr "\n" " ") " in *" $1 "*) return 0 ;; esac; return 1; }

if want curl; then for b in $(all_in_path curl) $(globs /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl); do add curl "$b"; done; fi
if want wget; then for b in $(all_in_path wget); do add wget "$b"; done; fi
if want git; then for b in $(all_in_path git); do add git "$b"; done; fi
if want openssl; then for b in $(all_in_path openssl) $(globs /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl); do add openssl "$b"; done; fi
PYS="$( { all_in_path python3; for d in $(echo "$PATH" | tr ':' '\n'); do globs "$d/python3.[0-9]" "$d/python3.[0-9][0-9]"; done
          globs "$HOME/.pyenv/versions/*/bin/python3" "$HOME/.local/share/uv/python/*/bin/python3" \
                "$HOME/miniconda3/bin/python3" "$HOME/anaconda3/bin/python3" "$HOME/miniforge3/bin/python3" "/opt/conda/bin/python3"
          [ -x /usr/bin/python3 ] && echo /usr/bin/python3; } 2>/dev/null)"
for k in python requests pip; do if want $k; then for b in $PYS; do add $k "$b"; done; fi; done
if want node; then
  for b in $(all_in_path node) $(globs "$HOME/.nvm/versions/node/*/bin/node" "$HOME/.volta/tools/image/node/*/bin/node" \
      "$HOME/.local/share/fnm/node-versions/*/installation/bin/node" "$HOME/Library/Application Support/fnm/node-versions/*/installation/bin/node" \
      "$HOME/.asdf/installs/nodejs/*/bin/node" "$HOME/.local/share/mise/installs/node/*/bin/node"); do add node "$b"; done
fi
if want bun; then for b in $(all_in_path bun) $(globs "$HOME/.bun/bin/bun"); do add bun "$b"; done; fi
if want deno; then for b in $(all_in_path deno) $(globs "$HOME/.deno/bin/deno"); do add deno "$b"; done; fi
if want ruby; then for b in $(all_in_path ruby); do add ruby "$b"; done; fi
if want perl; then for b in $(all_in_path perl); do add perl "$b"; done; fi
if want php; then for b in $(all_in_path php); do add php "$b"; done; fi
if want go; then for b in $(all_in_path go) $(globs /usr/local/go/bin/go); do add go "$b"; done; fi
if want java; then
  if [ "$OS" = Darwin ]; then /usr/libexec/java_home >/dev/null 2>&1 && add java "$(/usr/libexec/java_home)/bin/java"
  else for b in $(all_in_path java); do add java "$b"; done; fi
fi

version_of() {
  case "$1" in
    curl|wget) "$2" --version 2>/dev/null | head -1 | awk '{print $2}' ;;
    git) "$2" --version 2>/dev/null | awk '{print $3}' ;;
    openssl) "$2" version 2>/dev/null | awk '{print $1"-"$2}' ;;
    python|requests|pip) "$2" -c 'import sys;print(sys.version.split()[0])' 2>/dev/null ;;
    node|bun) "$2" --version 2>/dev/null | head -1 ;;
    deno) "$2" --version 2>/dev/null | head -1 | awk '{print $2}' ;;
    ruby) "$2" -e 'print RUBY_VERSION' 2>/dev/null ;;
    perl) "$2" -e 'print $^V' 2>/dev/null ;;
    php) "$2" -r 'echo PHP_VERSION;' 2>/dev/null ;;
    go) "$2" env GOVERSION 2>/dev/null ;;
    java) "$2" -version 2>&1 | head -1 | awk -F'"' '{print $2}' ;;
  esac
}

run_one() { # kind bin host -> result word; detail appended to log
  local i=1 res out="$TMP/out.$$"
  while :; do
    "probe_$1" "$2" "$3" > "$out" 2>&1
    if grep -qE '^(NO_REQUESTS|NO_IO_SOCKET_SSL|BUILD_FAILED)' "$out"; then echo SKIP; return; fi
    res="$(classify "$out")"
    { echo "== $1 $2 -> $3 (attempt $i): $res"; head -c 600 "$out"; echo; } >> "$TMP/log"
    [ "$res" != NETERR ] || [ "$i" -ge "$RETRIES" ] && break
    i=$((i + 1)); sleep 3
  done
  echo "$res"
}

# ---- run ---------------------------------------------------------------------
for v in HTTPS_PROXY https_proxy ALL_PROXY all_proxy; do
  eval "val=\${$v:-}"
  [ -n "$val" ] && echo "WARNING: \$$v=$val is set. A TLS-inspecting proxy re-signs traffic, so results describe the proxy, not the client." >&2
done

printf '%-9s %-62s %-12s %-10s %-10s %-10s %s\n' KIND BINARY VERSION TEST-1 TEST-2 CONTROL VERDICT
EXPOSED=0; SAFE=0; OTHER=0
while IFS="$(printf '\t')" read -r kind bin; do
  ver="$(version_of "$kind" "$bin")"
  r1="$(run_one "$kind" "$bin" "$H1")"
  [ "$r1" = SKIP ] && continue
  r2="$(run_one "$kind" "$bin" "$H2")"
  rc="$(run_one "$kind" "$bin" "$CONTROL")"
  if [ "$r1" = CONNECTED ] || [ "$r2" = CONNECTED ]; then verdict=EXPOSED; EXPOSED=$((EXPOSED + 1))
  elif [ "$rc" = REJECTED ]; then verdict="BROKEN (rejects control host)"; OTHER=$((OTHER + 1))
  elif [ "$r1" = REJECTED ] && [ "$r2" = REJECTED ] && [ "$rc" = CONNECTED ]; then verdict=SAFE; SAFE=$((SAFE + 1))
  else verdict="INCONCLUSIVE (network)"; OTHER=$((OTHER + 1)); fi
  short="$bin"; [ ${#short} -gt 62 ] && short="...${bin: -59}"
  printf '%-9s %-62s %-12s %-10s %-10s %-10s %s\n' "$kind" "$short" "${ver:-?}" "$r1" "$r2" "$rc" "$verdict"
done < "$CANDIDATES"

[ -f "$TMP/skipped" ] && { echo; cat "$TMP/skipped"; }
echo
echo "Summary: $EXPOSED exposed, $SAFE safe, $OTHER inconclusive/broken."
if [ -n "${PROBE_LOG:-}" ]; then cp "$TMP/log" "$PROBE_LOG" && echo "Raw probe output saved to $PROBE_LOG"; fi
[ "$EXPOSED" -gt 0 ] && exit 1
[ "$OTHER" -gt 0 ] && exit 3
exit 0
