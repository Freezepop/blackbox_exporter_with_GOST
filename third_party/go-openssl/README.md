# OpenSSL bindings for Go

Forked from https://github.com/libp2p/openssl (unmaintained) to add:

1. Fix build by golang 1.13.
2. Fix build on Apple M1.
3. Fix static build.
4. Fix error extraction on key reading.
5. Bindings for DANE.
6. Optional static linking with GOST engine for Russian GOST crypto algorithms.

### License

Copyright (C) 2017. See AUTHORS.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

### Using on macOS
1. Install [homebrew](http://brew.sh/)
2. `$ brew install openssl` or `$ brew install openssl@1.1`

### Using on Windows
1. Install [mingw-w64](http://mingw-w64.sourceforge.net/)
2. Install [pkg-config-lite](http://sourceforge.net/projects/pkgconfiglite)
3. Build (or install precompiled) openssl for mingw32-w64
4. Set __PKG\_CONFIG\_PATH__ to the directory containing openssl.pc
   (i.e. c:\mingw64\mingw64\lib\pkgconfig)

### Static linking with GOST engine

The library can optionally statically link the [GOST engine][gost-engine],
which provides Russian GOST cryptographic algorithms (GOST 28147-89,
Streebog, Kuznyechik, Magma, etc.). After linking, GOST ciphers and digests
are available immediately through the standard `GetCipherByName` /
`GetDigestByName` API — no runtime engine loading is needed.

GOST engine requires OpenSSL 3.0+. The `openssl_gost` build tag can be used
with or without `openssl_static`: static GOST libraries link against
whichever OpenSSL (static or dynamic) is configured by the other build tags.

#### Prerequisites

Build OpenSSL (static, if using `openssl_static`) and GOST engine as static
libraries:

```bash
# Build OpenSSL 3.4.1 static.
git clone --depth 1 --branch openssl-3.4.1 https://github.com/openssl/openssl.git
cd openssl
./config no-shared -fPIC --prefix=$PWD/../openssl-install --openssldir=/etc/ssl
make -j$(nproc) && make install_sw
cd ..

# Build GOST engine v3.0.3 static.
git clone --depth 1 --branch v3.0.3 --recursive https://github.com/gost-engine/engine.git gost-engine
cd gost-engine

# GOST engine builds a shared library by default; switch it to static
# and disable the install(EXPORT) that is incompatible with the static target.
sed -i 's/add_library(lib_gost_engine SHARED/add_library(lib_gost_engine STATIC/' CMakeLists.txt
sed -i '/install(TARGETS lib_gost_engine EXPORT/,/)/s/^/#disabled: /' CMakeLists.txt

mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
      -DOPENSSL_ROOT_DIR=$PWD/../../openssl-install ..
cmake --build . --target lib_gost_engine gost_core gost_err
```

#### Creating the pkg-config file

The `openssl_gost` build tag uses `pkg-config` to find the GOST engine
libraries, just like `openssl_static` uses it for OpenSSL. Create a
`gost-engine.pc` file so pkg-config can locate the static libraries:

```bash
GOST=$PWD/..   # Path to the gost-engine directory (parent of build/).

cat > /usr/local/lib/pkgconfig/gost-engine.pc << EOF
prefix=$GOST
build_dir=\${prefix}/build

Name: gost-engine
Description: Reference implementation of GOST crypto algorithms for OpenSSL
Version: 3.0.3
Cflags: -I\${prefix}
Libs: \${build_dir}/libgost.a \${build_dir}/libgost_core.a \${build_dir}/libgost_err.a
EOF
```

#### Building with GOST engine

Use the `openssl_gost` build tag (optionally combined with `openssl_static`).
No `CGO_LDFLAGS` is needed — pkg-config handles everything:

```bash
PKG_CONFIG_PATH=/path/to/openssl-install/lib64/pkgconfig \
go build -tags "openssl_static openssl_gost" ./...
```

#### Using GOST algorithms

After building with `openssl_gost`, GOST ciphers and digests are available
through the standard API. The engine is loaded automatically during package
initialization:

```go
import "github.com/tarantool/go-openssl"

// GOST 28147-89 cipher.
cipher, err := openssl.GetCipherByName("GOST 28147-89")

// Streebog (GOST R 34.11-2012) digests.
digest, err := openssl.GetDigestByName("streebog256")
digest, err = openssl.GetDigestByName("streebog512")

// Kuznyechik / Magma block ciphers.
cipher, err := openssl.GetCipherByName("kuznyechik-cbc")
cipher, err = openssl.GetCipherByName("magma-cbc")
```

[gost-engine]: https://github.com/gost-engine/engine
