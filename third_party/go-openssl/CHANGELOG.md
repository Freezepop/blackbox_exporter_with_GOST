# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html) except to the first release.

## [Unreleased]

### Added

### Changed

### Fixed

## [v1.4.2] - 2026-08-17

The release fixes the floating-point exception during GOST engine
initialization.

### Fixed

- The statically linked OpenSSL 3.x with the GOST engine leads to
  floating-point exception during initialization because of
  incompatible OpenSSL initialization routine.

## [v1.4.1] - 2026-07-17

The release fixes unavailable GOST ciphers due to a cert/key load.

### Fixed

- The statically linked GOST engine loaded but not initialized or set as
  default, breaking GOST PEM key/certificate decoding (#28).

## [v1.4.0] - 2026-07-08

The release adds optional static linking with the GOST engine, making Russian
GOST cryptographic algorithms available through a static linked binary.

### Added

- Optional static linking with the GOST engine for OpenSSL,
  enabled with the `openssl_gost` build tag. When combined with static
  GOST engine libraries (provided via `pkg-config`), Russian GOST
  cryptographic algorithms (GOST 28147-89, Streebog, Kuznyechik, Magma,
  etc.) become available through the standard `GetCipherByName` /
  `GetDigestByName` API without any runtime engine loading. Requires
  OpenSSL 3.0+ (#26).

## [v1.3.0] - 2026-07-07

The release adds server-side ALPN protocol selection for serving standard
gRPC/HTTP2 clients.

### Added

- ctx: `SetServerALPNProtos` for server-side ALPN protocol selection. It
  registers `SSL_CTX_set_alpn_select_cb` and delegates the match to OpenSSL's
  `SSL_select_next_proto`, so a server selects and echoes a protocol (e.g. `h2`)
  from the client's advertised list, which is required for serving standard
  gRPC/HTTP2 clients. The pre-existing `SetNextProtos` only sets the client-side
  advertised list and does not select on the server. The list must be non-empty;
  an empty list is rejected so the server never installs a callback that would
  abort every ALPN-offering handshake. Works with per-vhost SNI: when the
  servername callback swaps the `Ctx` via `SetSSLCtx`, selection runs against the
  swapped-in `Ctx`'s list.
- ssl: `GetALPNNegotiated` (promoted to `Conn`) returns the protocol selected via
  ALPN during the handshake, wrapping `SSL_get0_alpn_selected`.

## [v1.2.2] - 2026-04-03

The release fixes build with OpenSSL v1.

### Fixed

- Guard `SSL_trace` usage with `OPENSSL_NO_SSL_TRACE` check to fix build on
  OpenSSL configurations without SSL trace support.

## [v1.2.1] - 2025-01-27

The release fixes tests on Tarantool Cluster Manager.

### Changed

- stretchr/testify dependency decreased to v1.10.0.

## [v1.2.0] - 2025-01-21

The release introduces `Close()` method of the Ctx, that
could be called to clean internal resouces.

### Added

- ctx: new method for closing context and clean internal resources
  (TNTP-5472).

## [v1.1.1] - 2024-09-27

The small release include fixes for problems found by Svacer.

### Fixed

- Unchecked `X509_STORE_CTX_get_ex_data` return value (#16).

## [v1.1.0] - 2024-09-02

The release adds more bindings.

### Added

- Bindings for [DANE](https://docs.openssl.org/1.1.1/man3/SSL_CTX_dane_enable/) (#14).
- Bindings for [TLS handshake tracing](https://docs.openssl.org/master/man3/SSL_CTX_set_msg_callback/) (#14).
- Bindings for `X509_digest()` (#14).
- Bindings for `X509_verify_cert_error_string()` (#14).
- Bindings for `SSL_get_version()` (#14).

## [v1.0.0] - 2024-02-09

The first release with a number of fixes. Since `libp2p/openssl` is not
supported any more we need to support our version for usage in the Golang
connector `tarantool/go-tarantool`.

See [releases of `libp2p/openssl`](https://github.com/libp2p/go-openssl/releases)
for previous changes history.

### Added

- DialContext function (#10).

### Fixed

- Build by Golang 1.13 (#6).
- Build with OpenSSL < 1.1.1 (#7).
- Build on macOS as a static library (#8).
- Build on macOS with Apple M1 (#8).
- Random errors in the code caused by an invalid OpenSSL error handling in
  LoadPrivateKeyFromPEM, LoadPrivateKeyFromPEMWithPassword,
  LoadPrivateKeyFromDER and LoadPublicKeyFromPEM (#9).
