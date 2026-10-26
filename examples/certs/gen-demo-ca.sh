#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
#
# Regenerates the static DEMO certificate hierarchy used by the PoC examples:
#
#   SPDMLIB DEMO CA                     (root, self-signed)
#   └─ SPDMLIB SIGNING DEMO             (intermediate CA)
#      └─ SPDMLIB IDENTITY SIGNING DEMO (issues per-device IDevID certificates)
#
# The per-device chain below it (IDEVID → LDEVID → LEAF) is not stored here; the
# examples' build.rs generates it on every clean build, signed with the
# identity-signing key this script writes.
#
# Only the three certificates and the identity-signing key are kept. The root and
# signing private keys are discarded, as an offline vendor root would be.
#
# DEMO MATERIAL ONLY: the identity-signing private key is public in this
# repository. Never trust this hierarchy outside of host testing.
#
# Usage: examples/certs/gen-demo-ca.sh   (requires OpenSSL 3.4+)
set -euo pipefail

out="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The slot 0 leaf should not expire (DSP0274 1.4 §10.9); CAs above it must not
# expire earlier.
not_before="$(date -u +%Y%m%d%H%M%SZ)"
not_after="99991231235959Z"

cat > "$work/ext.cnf" <<'CNF'
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
CNF

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$work/$1.key.pem"; }
serial() { echo "0x$(openssl rand -hex 15)"; }  # 120-bit positive serial

# issue <name> <CN> <issuer-name|self>
issue() {
    local name="$1" cn="$2" issuer="$3"
    key "$name"
    openssl req -new -key "$work/$name.key.pem" -subj "/CN=$cn" -out "$work/$name.csr"
    if [ "$issuer" = self ]; then
        openssl x509 -req -in "$work/$name.csr" -key "$work/$name.key.pem" \
            -extfile "$work/ext.cnf" -extensions ca -sha384 -set_serial "$(serial)" \
            -not_before "$not_before" -not_after "$not_after" -out "$work/$name.cert.pem"
    else
        openssl x509 -req -in "$work/$name.csr" \
            -CA "$work/$issuer.cert.pem" -CAkey "$work/$issuer.key.pem" \
            -extfile "$work/ext.cnf" -extensions ca -sha384 -set_serial "$(serial)" \
            -not_before "$not_before" -not_after "$not_after" -out "$work/$name.cert.pem"
    fi
    openssl x509 -in "$work/$name.cert.pem" -outform DER -out "$out/$name.cert.der"
}

issue demo-ca               "SPDMLIB DEMO CA"               self
issue signing-demo          "SPDMLIB SIGNING DEMO"          demo-ca
issue identity-signing-demo "SPDMLIB IDENTITY SIGNING DEMO" signing-demo

openssl verify -x509_strict -CAfile "$work/demo-ca.cert.pem" \
    -untrusted "$work/signing-demo.cert.pem" "$work/identity-signing-demo.cert.pem"

# PKCS#8 DER, read by build.rs to sign each build's IDevID.
openssl pkcs8 -topk8 -nocrypt -in "$work/identity-signing-demo.key.pem" -outform DER \
    -out "$out/identity-signing-demo.key.der"

echo "wrote: $(cd "$out" && ls ./*.der | tr '\n' ' ')"
