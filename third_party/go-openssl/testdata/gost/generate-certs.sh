#!/usr/bin/env bash
set -euo pipefail

# Generate a self-signed GOST 2012-256 client certificate for tests.
# Requires system OpenSSL with GOST engine/provider enabled.

OUT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$OUT_DIR"

# Basic check for GOST support.
if ! openssl ciphers 2>/dev/null | tr ':' '\n' | grep -qi 'GOST'; then
  echo "error: OpenSSL has no GOST support (no GOST ciphers in 'openssl ciphers')." >&2
  exit 1
fi

rm -f client.key client.crt

# GOST 34.10-2012 (256-bit), paramset A; Streebog-256 digest.
openssl req -new -x509 -nodes \
  -newkey gost2012_256 -pkeyopt paramset:A \
  -md_gost12_256 \
  -days 3650 \
  -subj "/C=RU/O=TQE Test/CN=test-gost-client" \
  -keyout client.key \
  -out client.crt
