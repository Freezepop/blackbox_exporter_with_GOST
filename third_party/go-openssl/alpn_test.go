// Copyright (C) 2026. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

// Characterization tests for ALPN negotiation.
//
// This package has no ALPN getter (no SSL_get0_alpn_selected binding), so the
// only way to observe the negotiated protocol is to put a crypto/tls peer on
// the other end and read its ConnectionState().NegotiatedProtocol.
//
// Ctx.SetNextProtos wraps SSL_CTX_set_alpn_protos, the *client*-side ALPN
// mechanism, while Ctx.SetServerALPNProtos registers SSL_CTX_set_alpn_select_cb,
// the *server*-side callback that actually selects and echoes a protocol. These
// tests exercise both directions.

import (
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
)

// openSSLCtxALPN builds a Ctx configured like OpenSSLConstructor, additionally
// advertising the given ALPN protocols via SetNextProtos.
func openSSLCtxALPN(t *testing.T, protos []string) *Ctx {
	ctx, err := NewCtx()
	if err != nil {
		t.Fatal(err)
	}
	ctx.SetVerify(VerifyNone, passThruVerify(t))
	key, err := LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.UsePrivateKey(key); err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCertificateFromPEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.UseCertificate(cert); err != nil {
		t.Fatal(err)
	}
	if err := ctx.SetCipherList("AES128-SHA"); err != nil {
		t.Fatal(err)
	}
	if err := ctx.SetNextProtos(protos); err != nil {
		t.Fatal(err)
	}
	return ctx
}

// stdlibConfigALPN mirrors StdlibConstructor's config plus ALPN protocols.
func stdlibConfigALPN(t *testing.T, protos []string) *tls.Config {
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		NextProtos:         protos,
	}
}

// handshakeBoth drives both peers' handshakes concurrently and fails on error.
func handshakeBoth(t *testing.T, server, client HandshakingConn) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = server.Handshake() }()
	go func() { defer wg.Done(); errs[1] = client.Handshake() }()
	wg.Wait()
	if errs[0] != nil {
		t.Fatalf("server handshake failed: %v", errs[0])
	}
	if errs[1] != nil {
		t.Fatalf("client handshake failed: %v", errs[1])
	}
}

// Control case: stdlib <-> stdlib. Proves the harness and cert setup are sound,
// and that stdlib server-side ALPN selection works (expected: "h2" both sides).
func TestALPN_StdlibServer_StdlibClient(t *testing.T) {
	serverConn, clientConn := NetPipe(t)
	defer serverConn.Close()
	defer clientConn.Close()

	cfg := stdlibConfigALPN(t, []string{"h2"})
	server := tls.Server(serverConn, cfg)
	client := tls.Client(clientConn, cfg)
	defer close_both(server, client)

	handshakeBoth(t, server, client)

	srv := server.ConnectionState().NegotiatedProtocol
	cli := client.ConnectionState().NegotiatedProtocol
	t.Logf("stdlib server NegotiatedProtocol=%q, stdlib client NegotiatedProtocol=%q", srv, cli)
	if srv != "h2" || cli != "h2" {
		t.Errorf("expected both sides to negotiate h2; got server=%q client=%q", srv, cli)
	}
}

// Client side of go-openssl: openssl client <-> stdlib server.
// SSL_CTX_set_alpn_protos is the client mechanism, so the openssl client should
// correctly advertise h2 and the stdlib server should select it (expected: "h2").
func TestALPN_StdlibServer_OpenSSLClient(t *testing.T) {
	serverConn, clientConn := NetPipe(t)
	defer serverConn.Close()
	defer clientConn.Close()

	server := tls.Server(serverConn, stdlibConfigALPN(t, []string{"h2"}))
	clientCtx := openSSLCtxALPN(t, []string{"h2"})
	client, err := Client(clientConn, clientCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer close_both(server, client)

	handshakeBoth(t, server, client)

	// Measured on the stdlib server, which reports what it selected from the
	// client's advertised list.
	got := server.ConnectionState().NegotiatedProtocol
	t.Logf("openssl client advertised h2 -> stdlib server NegotiatedProtocol=%q", got)
	if got != "h2" {
		t.Errorf("openssl client ALPN advertise broken: stdlib server negotiated %q, want %q", got, "h2")
	}
}

// Server side of go-openssl: openssl server <-> stdlib client. This is the
// gRPC-relevant case. The openssl server calls SetServerALPNProtos(["h2"]),
// which registers SSL_CTX_set_alpn_select_cb, so it selects and echoes "h2".
// A standard (gRPC-style) client therefore observes "h2".
func TestALPN_OpenSSLServer_StdlibClient(t *testing.T) {
	serverConn, clientConn := NetPipe(t)
	defer serverConn.Close()
	defer clientConn.Close()

	serverCtx := openSSLCtxALPN(t, nil)
	if err := serverCtx.SetServerALPNProtos([]string{"h2"}); err != nil {
		t.Fatal(err)
	}
	server, err := Server(serverConn, serverCtx)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(clientConn, stdlibConfigALPN(t, []string{"h2"}))
	defer close_both(server, client)

	handshakeBoth(t, server, client)

	got := client.ConnectionState().NegotiatedProtocol
	t.Logf("openssl server SetServerALPNProtos([h2]) + stdlib client offering h2 -> client NegotiatedProtocol=%q", got)
	if got != "h2" {
		t.Errorf("server-side ALPN failed: client negotiated %q, want %q", got, "h2")
	}
}

// No mutual protocol: the openssl server offers only "h2" while the client
// offers only "http/1.1". SetServerALPNProtos must abort the handshake with a
// no_application_protocol alert (RFC 7301), so at least one side errors rather
// than silently completing without ALPN.
func TestALPN_OpenSSLServer_NoOverlap(t *testing.T) {
	serverConn, clientConn := NetPipe(t)
	defer serverConn.Close()
	defer clientConn.Close()

	serverCtx := openSSLCtxALPN(t, nil)
	if err := serverCtx.SetServerALPNProtos([]string{"h2"}); err != nil {
		t.Fatal(err)
	}
	server, err := Server(serverConn, serverCtx)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(clientConn, stdlibConfigALPN(t, []string{"http/1.1"}))
	defer close_both(server, client)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = server.Handshake() }()
	go func() { defer wg.Done(); errs[1] = client.Handshake() }()
	wg.Wait()

	t.Logf("no-overlap handshake result: server=%v client=%v", errs[0], errs[1])
	if errs[0] == nil && errs[1] == nil {
		t.Error("expected the handshake to fail with no ALPN overlap, but both sides succeeded")
	}
}

// A multi-entry server preference list must reach SSL_select_next_proto intact.
// The server offers two protocols but the client offers only "h2", so "h2" is
// the sole common protocol and must be selected regardless of preference-order
// semantics. This exercises the multi-entry, ctx-owned server buffer that
// SetServerALPNProtos hands to OpenSSL.
func TestALPN_OpenSSLServer_MultiProtoServerList(t *testing.T) {
	serverConn, clientConn := NetPipe(t)
	defer serverConn.Close()
	defer clientConn.Close()

	serverCtx := openSSLCtxALPN(t, nil)
	if err := serverCtx.SetServerALPNProtos([]string{"h2", "http/1.1"}); err != nil {
		t.Fatal(err)
	}
	server, err := Server(serverConn, serverCtx)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(clientConn, stdlibConfigALPN(t, []string{"h2"}))
	defer close_both(server, client)

	handshakeBoth(t, server, client)

	if got := client.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Errorf("client negotiated %q, want %q", got, "h2")
	}
	if got := server.GetALPNNegotiated(); got != "h2" {
		t.Errorf("server GetALPNNegotiated() = %q, want %q", got, "h2")
	}
}

// SetServerALPNProtos must reject an empty list. Installing the selection
// callback with nothing to select would make the server abort every handshake
// in which the client offers ALPN, turning "no ALPN configured" into a footgun.
func TestALPN_SetServerALPNProtos_RejectsEmpty(t *testing.T) {
	ctx, err := NewCtx()
	if err != nil {
		t.Fatal(err)
	}
	for _, protos := range [][]string{nil, {}} {
		if err := ctx.SetServerALPNProtos(protos); err == nil {
			t.Errorf("SetServerALPNProtos(%#v) = nil; want error for empty list", protos)
		}
	}
}

// SetServerALPNProtos must reject a list containing an out-of-range protocol.
// The ALPN wire format prefixes each protocol with a single length byte, so a
// zero-length name is unrepresentable and a name longer than 255 bytes cannot
// be encoded. Rejecting these up front keeps such a list from ever reaching the
// selection callback.
func TestALPN_SetServerALPNProtos_RejectsInvalidProto(t *testing.T) {
	ctx, err := NewCtx()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"empty proto":         {""},
		"too long proto":      {strings.Repeat("a", 256)},
		"valid then empty":    {"h2", ""},
		"valid then too long": {"h2", strings.Repeat("a", 256)},
	}
	for name, protos := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ctx.SetServerALPNProtos(protos); err == nil {
				t.Errorf("SetServerALPNProtos(%#v) = nil; want error for out-of-range proto", protos)
			}
		})
	}
}

// Multi-vhost SNI: when the servername callback swaps in a different Ctx via
// SetSSLCtx, ALPN selection must run against the *swapped* Ctx, not the original
// listening Ctx. OpenSSL fires the servername callback before it performs ALPN
// selection and reads both the callback and the preference list from the
// then-current SSL_CTX, so each vhost's own SetServerALPNProtos governs what it
// negotiates. Each Ctx is configured with a single, distinct protocol, so the
// negotiated result reveals which Ctx did the selecting regardless of
// preference-order semantics. This is the case the reviewer was unsure about.
func TestALPN_OpenSSLServer_SNISwapCtx(t *testing.T) {
	// h2Ctx is the vhost selected by SNI; it prefers "h2".
	newSwapServer := func(t *testing.T, sniName string, configureVhost func(*Ctx)) (*Conn, net.Conn, net.Conn) {
		serverConn, clientConn := NetPipe(t)

		defaultCtx := openSSLCtxALPN(t, nil)
		if err := defaultCtx.SetServerALPNProtos([]string{"http/1.1"}); err != nil {
			t.Fatal(err)
		}
		vhostCtx := openSSLCtxALPN(t, nil)
		configureVhost(vhostCtx)

		defaultCtx.SetTLSExtServernameCallback(func(ssl *SSL) SSLTLSExtErr {
			if ssl.GetServername() == sniName {
				ssl.SetSSLCtx(vhostCtx)
			}
			return SSLTLSExtErrOK
		})

		server, err := Server(serverConn, defaultCtx)
		if err != nil {
			t.Fatal(err)
		}
		return server, serverConn, clientConn
	}

	// The swapped-in vhost configured ALPN, so its protocol ("h2") is selected
	// even though the default listening Ctx would have picked "http/1.1".
	t.Run("swapped ctx selects its own protocol", func(t *testing.T) {
		server, serverConn, clientConn := newSwapServer(t, "h2.example", func(c *Ctx) {
			if err := c.SetServerALPNProtos([]string{"h2"}); err != nil {
				t.Fatal(err)
			}
		})
		defer serverConn.Close()
		defer clientConn.Close()

		cfg := stdlibConfigALPN(t, []string{"h2", "http/1.1"})
		cfg.ServerName = "h2.example"
		client := tls.Client(clientConn, cfg)
		defer close_both(server, client)

		handshakeBoth(t, server, client)

		got := client.ConnectionState().NegotiatedProtocol
		t.Logf("SNI h2.example -> client NegotiatedProtocol=%q", got)
		if got != "h2" {
			t.Errorf("SNI-swapped Ctx ALPN not applied: negotiated %q, want %q "+
				"(http/1.1 would mean the original Ctx did the selecting)", got, "h2")
		}
		if srv := server.GetALPNNegotiated(); srv != "h2" {
			t.Errorf("server-side GetALPNNegotiated() = %q, want %q", srv, "h2")
		}
	})

	// The swapped-in vhost did NOT configure server-side ALPN, so it opts out of
	// selection entirely: the default Ctx's protocols are not leaked to it, and
	// the handshake completes with no negotiated protocol.
	t.Run("swapped ctx without ALPN opts out", func(t *testing.T) {
		server, serverConn, clientConn := newSwapServer(t, "plain.example", func(c *Ctx) {})
		defer serverConn.Close()
		defer clientConn.Close()

		cfg := stdlibConfigALPN(t, []string{"h2", "http/1.1"})
		cfg.ServerName = "plain.example"
		client := tls.Client(clientConn, cfg)
		defer close_both(server, client)

		handshakeBoth(t, server, client)

		got := client.ConnectionState().NegotiatedProtocol
		t.Logf("SNI plain.example (vhost without ALPN) -> client NegotiatedProtocol=%q", got)
		if got != "" {
			t.Errorf("vhost without ALPN negotiated %q, want %q "+
				"(the default Ctx's protocols must not leak into the swapped vhost)", got, "")
		}
	})
}

// SetServerALPNProtos must snapshot its argument. Mutating the caller's slice
// after the call must not change what the server negotiates: if the mutation
// below leaked into the stored list, the server would look for "http/1.1" (which
// the client does not offer) and abort instead of selecting "h2".
func TestALPN_SetServerALPNProtos_CopiesSlice(t *testing.T) {
	serverConn, clientConn := NetPipe(t)
	defer serverConn.Close()
	defer clientConn.Close()

	serverCtx := openSSLCtxALPN(t, nil)
	protos := []string{"h2"}
	if err := serverCtx.SetServerALPNProtos(protos); err != nil {
		t.Fatal(err)
	}
	protos[0] = "http/1.1" // Must not affect the server's stored copy.

	server, err := Server(serverConn, serverCtx)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(clientConn, stdlibConfigALPN(t, []string{"h2"}))
	defer close_both(server, client)

	handshakeBoth(t, server, client)

	got := client.ConnectionState().NegotiatedProtocol
	t.Logf("post-mutation client NegotiatedProtocol=%q", got)
	if got != "h2" {
		t.Errorf("server aliased caller's slice: client negotiated %q, want %q", got, "h2")
	}
}

// Calling SetServerALPNProtos again must replace the previous list (and free the
// old ctx-owned buffer). The most recent configuration governs negotiation.
func TestALPN_SetServerALPNProtos_Rebind(t *testing.T) {
	serverConn, clientConn := NetPipe(t)
	defer serverConn.Close()
	defer clientConn.Close()

	serverCtx := openSSLCtxALPN(t, nil)
	if err := serverCtx.SetServerALPNProtos([]string{"http/1.1"}); err != nil {
		t.Fatal(err)
	}
	if err := serverCtx.SetServerALPNProtos([]string{"h2"}); err != nil {
		t.Fatal(err)
	}
	server, err := Server(serverConn, serverCtx)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(clientConn, stdlibConfigALPN(t, []string{"h2"}))
	defer close_both(server, client)

	handshakeBoth(t, server, client)

	if got := client.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Errorf("client negotiated %q, want %q (the second SetServerALPNProtos must win)", got, "h2")
	}
}
