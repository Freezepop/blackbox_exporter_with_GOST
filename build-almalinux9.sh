#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

sudo dnf -y install \
  gcc gcc-c++ git make cmake perl-core pkgconf-pkg-config \
  ca-certificates curl tar gzip python3 file

exec "${SOURCE_DIR}/scripts/build-gost-linux.sh" "$@"
