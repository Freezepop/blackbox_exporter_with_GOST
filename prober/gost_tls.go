//go:build gost

// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0.

package prober

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"time"

	pconfig "github.com/prometheus/common/config"
	goopenssl "github.com/tarantool/go-openssl"
)

const gostCipherList = "GOST2012-GOST8912-GOST8912:GOST2001-GOST89-GOST89:" +
	"GOST2012-KUZNYECHIK-KUZNYECHIK:GOST2012-MAGMA-MAGMA:@SECLEVEL=0"

// tlsStateBox transfers connection metadata from DialTLSContext to RoundTrip.
// Blackbox disables keep-alives, so one state belongs to one round trip.
type tlsStateBox struct {
	mu    sync.Mutex
	state tls.ConnectionState
}

func (b *tlsStateBox) set(state tls.ConnectionState) {
	b.mu.Lock()
	b.state = state
	b.mu.Unlock()
}

func (b *tlsStateBox) get() tls.ConnectionState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

type gostStateRoundTripper struct {
	next  http.RoundTripper
	state *tlsStateBox
}

func (rt *gostStateRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.next.RoundTrip(req)
	if err == nil && resp != nil {
		state := rt.state.get()
		resp.TLS = &state
	}
	return resp, err
}

type autoTLSRoundTripper struct {
	standard http.RoundTripper
	gost     http.RoundTripper
	logger   *slog.Logger
}

func wrapGOSTFallback(standard http.RoundTripper, cfg pconfig.HTTPClientConfig, logger *slog.Logger) (http.RoundTripper, error) {
	gost, err := newGOSTRoundTripper(cfg)
	if err != nil {
		return nil, err
	}
	return &autoTLSRoundTripper{standard: standard, gost: gost, logger: logger}, nil
}

func (rt *autoTLSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.standard.RoundTrip(req)
	if err == nil || req.URL.Scheme != "https" || !shouldTryGOST(err) {
		return resp, err
	}

	// A TLS handshake fails before net/http sends the HTTP request body, so the
	// same request can be retried on a fresh TCP connection.
	rt.logger.Info("Standard TLS is incompatible; retrying with the GOST backend", "err", err)
	return rt.gost.RoundTrip(req)
}

func shouldTryGOST(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return false
	}

	s := strings.ToLower(err.Error())
	for _, marker := range []string{
		"unsupported protocol",
		"protocol version not supported",
		"unsupported versions",
		"unconfigured cipher suite",
		"no cipher suite supported",
		"handshake failure",
		"illegal parameter",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func newGOSTRoundTripper(cfg pconfig.HTTPClientConfig) (http.RoundTripper, error) {
	state := &tlsStateBox{}
	dialTLS := newGOSTTLSDialer(cfg.TLSConfig, state)
	rt, err := pconfig.NewRoundTripperFromConfig(
		cfg,
		"http_probe_gost",
		pconfig.WithKeepAlivesDisabled(),
		pconfig.WithHTTP2Disabled(),
		pconfig.WithDialTLSContextFunc(dialTLS),
	)
	if err != nil {
		return nil, err
	}
	return &gostStateRoundTripper{next: rt, state: state}, nil
}

func newGOSTTLSDialer(cfg pconfig.TLSConfig, state *tlsStateBox) pconfig.DialTLSContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		trace := httptrace.ContextClientTrace(ctx)
		if trace != nil && trace.ConnectStart != nil {
			trace.ConnectStart(network, address)
		}
		raw, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if trace != nil && trace.ConnectDone != nil {
			trace.ConnectDone(network, address, err)
		}
		if err != nil {
			return nil, err
		}

		sslCtx, err := newGOSTContext(cfg)
		if err != nil {
			raw.Close()
			return nil, err
		}
		conn, err := goopenssl.Client(raw, sslCtx)
		if err != nil {
			sslCtx.Close()
			raw.Close()
			return nil, err
		}

		serverName := cfg.ServerName
		if serverName == "" {
			serverName, _, _ = net.SplitHostPort(address)
		}
		if serverName != "" && net.ParseIP(serverName) == nil {
			if err := conn.SetTlsExtHostName(serverName); err != nil {
				conn.Close()
				sslCtx.Close()
				return nil, err
			}
		}

		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}
		err = conn.Handshake()
		if err == nil && !cfg.InsecureSkipVerify && serverName != "" {
			err = conn.VerifyHostname(serverName)
		}
		tlsState := opensslConnectionState(conn)
		if trace != nil && trace.TLSHandshakeDone != nil {
			trace.TLSHandshakeDone(tlsState, err)
		}
		if err != nil {
			conn.Close()
			sslCtx.Close()
			return nil, err
		}
		_ = conn.SetDeadline(noDeadline)
		state.set(tlsState)
		return &opensslConn{Conn: conn, ctx: sslCtx}, nil
	}
}

var noDeadline = (func() (z time.Time) { return })()

type opensslConn struct {
	net.Conn
	ctx *goopenssl.Ctx
}

func (c *opensslConn) Close() error {
	return errors.Join(c.Conn.Close(), c.ctx.Close())
}

func newGOSTContext(cfg pconfig.TLSConfig) (*goopenssl.Ctx, error) {
	ctx, err := goopenssl.NewCtx()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*goopenssl.Ctx, error) {
		ctx.Close()
		return nil, err
	}

	minVersion := goopenssl.TLS1_VERSION
	if cfg.MinVersion != 0 {
		minVersion = goopenssl.Version(cfg.MinVersion)
	}
	maxVersion := goopenssl.TLS1_2_VERSION
	if cfg.MaxVersion != 0 && uint16(cfg.MaxVersion) < uint16(tls.VersionTLS12) {
		maxVersion = goopenssl.Version(cfg.MaxVersion)
	}
	if !ctx.SetMinProtoVersion(minVersion) || !ctx.SetMaxProtoVersion(maxVersion) {
		return fail(errors.New("failed to configure OpenSSL protocol versions"))
	}
	if err := ctx.SetCipherList(gostCipherList); err != nil {
		return fail(fmt.Errorf("GOST ciphers are unavailable (was blackbox built with openssl_gost?): %w", err))
	}
	_ = ctx.SetNextProtos([]string{"http/1.1"})

	if cfg.InsecureSkipVerify {
		ctx.SetVerify(goopenssl.VerifyNone, nil)
	} else {
		if err := loadGOSTRoots(ctx, cfg); err != nil {
			return fail(err)
		}
		ctx.SetVerify(goopenssl.VerifyPeer, nil)
	}
	if err := loadGOSTClientCertificate(ctx, cfg); err != nil {
		return fail(err)
	}
	return ctx, nil
}

func loadGOSTRoots(ctx *goopenssl.Ctx, cfg pconfig.TLSConfig) error {
	if cfg.CARef != "" {
		return errors.New("ca_ref is not supported by the GOST fallback")
	}
	if cfg.CA != "" {
		return ctx.GetCertificateStore().LoadCertificatesFromPEM([]byte(cfg.CA))
	}
	if cfg.CAFile != "" {
		return ctx.LoadVerifyLocations(cfg.CAFile, "")
	}
	if path := os.Getenv("SSL_CERT_FILE"); path != "" {
		return ctx.LoadVerifyLocations(path, "")
	}
	for _, path := range []string{"/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/certs/ca-certificates.crt"} {
		if _, err := os.Stat(path); err == nil {
			return ctx.LoadVerifyLocations(path, "")
		}
	}
	return errors.New("no CA bundle found for the GOST fallback")
}

func loadGOSTClientCertificate(ctx *goopenssl.Ctx, cfg pconfig.TLSConfig) error {
	if cfg.CertRef != "" || cfg.KeyRef != "" {
		return errors.New("cert_ref/key_ref are not supported by the GOST fallback")
	}
	certPEM, err := configBytes(string(cfg.Cert), cfg.CertFile)
	if err != nil || len(certPEM) == 0 {
		return err
	}
	keyPEM, err := configBytes(string(cfg.Key), cfg.KeyFile)
	if err != nil {
		return err
	}
	certBlocks := goopenssl.SplitPEM(certPEM)
	if len(certBlocks) == 0 {
		return errors.New("no PEM certificate found")
	}
	leaf, err := goopenssl.LoadCertificateFromPEM(certBlocks[0])
	if err != nil {
		return err
	}
	if err := ctx.UseCertificate(leaf); err != nil {
		return err
	}
	for _, block := range certBlocks[1:] {
		cert, err := goopenssl.LoadCertificateFromPEM(block)
		if err != nil {
			return err
		}
		if err := ctx.AddChainCertificate(cert); err != nil {
			return err
		}
	}
	key, err := goopenssl.LoadPrivateKeyFromPEMWithPassword(keyPEM, "")
	if err != nil {
		return err
	}
	return ctx.UsePrivateKey(key)
}

func configBytes(inline, file string) ([]byte, error) {
	if inline != "" {
		return []byte(inline), nil
	}
	if file != "" {
		return os.ReadFile(file)
	}
	return nil, nil
}

func opensslConnectionState(conn *goopenssl.Conn) tls.ConnectionState {
	state := tls.ConnectionState{
		Version:            opensslTLSVersion(conn.GetVersion()),
		HandshakeComplete:  true,
		NegotiatedProtocol: conn.GetALPNNegotiated(),
		CipherSuite:        0xfffe,
	}
	if name, err := conn.CurrentCipher(); err == nil {
		state.CipherSuite = gostCipherID(name)
	}
	certs, _ := conn.PeerCertificateChain()
	if leaf, err := conn.PeerCertificate(); err == nil {
		certs = append([]*goopenssl.Certificate{leaf}, certs...)
	}
	for _, cert := range certs {
		pemBytes, err := cert.MarshalPEM()
		if err != nil {
			continue
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			continue
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			state.PeerCertificates = append(state.PeerCertificates, parsed)
		}
	}
	if len(state.PeerCertificates) > 0 {
		state.VerifiedChains = [][]*x509.Certificate{state.PeerCertificates}
	}
	return state
}

func opensslTLSVersion(v string) uint16 {
	switch v {
	case "TLSv1", "TLSv1.0":
		return tls.VersionTLS10
	case "TLSv1.1":
		return tls.VersionTLS11
	case "TLSv1.2":
		return tls.VersionTLS12
	case "TLSv1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
}

func gostCipherID(name string) uint16 {
	switch strings.ToUpper(name) {
	case "GOST2001-GOST89-GOST89":
		return 0x0081
	case "GOST2012-GOST8912-GOST8912":
		return 0xff85
	case "GOST2012-KUZNYECHIK-KUZNYECHIK":
		return 0xc100
	case "GOST2012-MAGMA-MAGMA":
		return 0xc101
	default:
		// The context only advertises GOST suites. Preserve that fact even if a
		// newer engine returns a cipher spelling not yet present in this table.
		return 0xfffe
	}
}
