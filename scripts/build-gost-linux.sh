#!/usr/bin/env bash
set -euo pipefail

GO_VERSION=${GO_VERSION:-1.26.4}
OPENSSL_VERSION=${OPENSSL_VERSION:-3.4.1}
GOST_ENGINE_VERSION=${GOST_ENGINE_VERSION:-3.0.3}
VERSION=${VERSION:-0.28.0-gost-auto}
JOBS=${JOBS:-4}

SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_ROOT=${BLACKBOX_GOST_BUILD_DIR:-"${SOURCE_DIR}/.build-gost"}
DIST_DIR=${BLACKBOX_GOST_DIST_DIR:-"${SOURCE_DIR}/dist"}

case "$(uname -m)" in
  x86_64) GO_ARCH=amd64 ;;
  aarch64|arm64) GO_ARCH=arm64 ;;
  *) echo "Unsupported native architecture: $(uname -m)" >&2; exit 1 ;;
esac

BUILD_DIR="${BUILD_ROOT}/go${GO_VERSION}-openssl${OPENSSL_VERSION}-gost${GOST_ENGINE_VERSION}-${GO_ARCH}"
REVISION=${REVISION:-$(git -C "${SOURCE_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)}
BRANCH=${BRANCH:-$(git -C "${SOURCE_DIR}" branch --show-current 2>/dev/null || echo unknown)}
BRANCH=${BRANCH:-unknown}
BUILD_USER=${BUILD_USER:-$(id -un)@$(hostname)}
BUILD_DATE=${BUILD_DATE:-$(date -u +%Y%m%d-%H:%M:%S)}

for cmd in gcc g++ git make cmake perl pkg-config curl tar gzip python3 sha256sum; do
  command -v "${cmd}" >/dev/null || {
    echo "Missing build dependency: ${cmd}" >&2
    exit 1
  }
done

mkdir -p "${BUILD_DIR}" "${DIST_DIR}"

GO_ARCHIVE="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
if [[ ! -x "${BUILD_DIR}/go/bin/go" ]]; then
  curl --fail --location --output "${BUILD_DIR}/${GO_ARCHIVE}" "https://go.dev/dl/${GO_ARCHIVE}"
  curl --fail --location --output "${BUILD_DIR}/go-downloads.json" "https://go.dev/dl/?mode=json&include=all"
  GO_SHA256=$(python3 -c 'import json,sys; name=sys.argv[2]; data=json.load(open(sys.argv[1])); print(next(f["sha256"] for r in data for f in r["files"] if f["filename"] == name))' "${BUILD_DIR}/go-downloads.json" "${GO_ARCHIVE}")
  printf '%s  %s\n' "${GO_SHA256}" "${BUILD_DIR}/${GO_ARCHIVE}" | sha256sum --check
  mkdir -p "${BUILD_DIR}/go"
  tar -C "${BUILD_DIR}/go" --strip-components=1 -xzf "${BUILD_DIR}/${GO_ARCHIVE}"
fi

if [[ ! -d "${BUILD_DIR}/openssl/.git" ]]; then
  git clone --depth 1 --branch "openssl-${OPENSSL_VERSION}" https://github.com/openssl/openssl.git "${BUILD_DIR}/openssl"
fi
if [[ ! -f "${BUILD_DIR}/openssl-install/lib/libssl.a" && ! -f "${BUILD_DIR}/openssl-install/lib64/libssl.a" ]]; then
  (
    cd "${BUILD_DIR}/openssl"
    ./config no-shared no-tests -fPIC --prefix="${BUILD_DIR}/openssl-install" --openssldir=/etc/ssl
    make -j"${JOBS}"
    make install_sw
  )
fi

OPENSSL_LIB_DIR=$(dirname "$(find "${BUILD_DIR}/openssl-install" -name libssl.a -type f -print -quit)")
if [[ -z "${OPENSSL_LIB_DIR}" || ! -f "${OPENSSL_LIB_DIR}/libssl.a" ]]; then
  echo "Static OpenSSL library was not found" >&2
  exit 1
fi

if [[ ! -d "${BUILD_DIR}/gost-engine/.git" ]]; then
  git clone --depth 1 --branch "v${GOST_ENGINE_VERSION}" --recursive https://github.com/gost-engine/engine.git "${BUILD_DIR}/gost-engine"
  sed -i 's/add_library(lib_gost_engine SHARED/add_library(lib_gost_engine STATIC/' "${BUILD_DIR}/gost-engine/CMakeLists.txt"
  sed -i '/install(TARGETS lib_gost_engine EXPORT/,/)/s/^/# disabled for static build: /' "${BUILD_DIR}/gost-engine/CMakeLists.txt"
fi
if [[ ! -f "${BUILD_DIR}/gost-engine/build/libgost.a" ]]; then
  cmake -S "${BUILD_DIR}/gost-engine" -B "${BUILD_DIR}/gost-engine/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DOPENSSL_ROOT_DIR="${BUILD_DIR}/openssl-install" \
    -DOPENSSL_ENGINES_DIR="${OPENSSL_LIB_DIR}/engines-3"
  cmake --build "${BUILD_DIR}/gost-engine/build" --parallel "${JOBS}" --target lib_gost_engine gost_core gost_err
fi

mkdir -p "${BUILD_DIR}/pkgconfig"
GOST_ROOT="${BUILD_DIR}/gost-engine"
GOST_PC="${BUILD_DIR}/pkgconfig/gost-engine.pc"
printf '%s\n' \
  "prefix=${GOST_ROOT}" \
  'build_dir=${prefix}/build' \
  '' \
  'Name: gost-engine' \
  'Description: Reference GOST engine for OpenSSL' \
  "Version: ${GOST_ENGINE_VERSION}" \
  'Cflags: -I${prefix}' \
  'Libs: ${build_dir}/libgost.a ${build_dir}/libgost_core.a ${build_dir}/libgost_err.a' \
  > "${GOST_PC}"

export PKG_CONFIG_PATH="${BUILD_DIR}/pkgconfig:${OPENSSL_LIB_DIR}/pkgconfig"
export CGO_ENABLED=1

cd "${SOURCE_DIR}"
"${BUILD_DIR}/go/bin/go" test -tags 'gost openssl_static openssl_gost' ./prober \
  -run '^(TestShouldTryGOST|TestAutoTLSRoundTripper|TestStaticallyLinkedGOSTEngine|TestGOSTHTTPRoundTrip)' -count=1

"${BUILD_DIR}/go/bin/go" build \
  -tags 'gost openssl_static openssl_gost' \
  -trimpath \
  -ldflags "-s -w -extldflags=-static \
    -X github.com/prometheus/common/version.Version=${VERSION} \
    -X github.com/prometheus/common/version.Revision=${REVISION} \
    -X github.com/prometheus/common/version.Branch=${BRANCH} \
    -X github.com/prometheus/common/version.BuildUser=${BUILD_USER} \
    -X github.com/prometheus/common/version.BuildDate=${BUILD_DATE}" \
  -o "${DIST_DIR}/blackbox_exporter-gost" .

"${DIST_DIR}/blackbox_exporter-gost" --version
file "${DIST_DIR}/blackbox_exporter-gost"
ldd "${DIST_DIR}/blackbox_exporter-gost" || true
(
  cd "${DIST_DIR}"
  sha256sum blackbox_exporter-gost > blackbox_exporter-gost.sha256
)
