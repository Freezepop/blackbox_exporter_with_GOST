//go:build gost && openssl_gost

package prober

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	pconfig "github.com/prometheus/common/config"
	goopenssl "github.com/tarantool/go-openssl"
)

func TestStaticallyLinkedGOSTEngineProvidesTLSCiphers(t *testing.T) {
	ctx, err := newGOSTContext(pconfig.TLSConfig{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx.Close()
}

func TestGOSTHTTPRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version goopenssl.Version
	}{
		{"TLS1.0", goopenssl.TLS1_VERSION},
		{"TLS1.2", goopenssl.TLS1_2_VERSION},
	} {
		t.Run(tc.name, func(t *testing.T) { testGOSTHTTPRoundTrip(t, tc.version) })
	}
}

func testGOSTHTTPRoundTrip(t *testing.T, version goopenssl.Version) {
	t.Helper()
	serverCtx, err := goopenssl.NewCtxFromFiles(
		"../third_party/go-openssl/testdata/gost/client.crt",
		"../third_party/go-openssl/testdata/gost/client.key",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer serverCtx.Close()
	serverCtx.SetVerify(goopenssl.VerifyNone, nil)
	serverCtx.SetMinProtoVersion(version)
	serverCtx.SetMaxProtoVersion(version)
	if err := serverCtx.SetCipherList(gostCipherList); err != nil {
		t.Fatal(err)
	}
	listener, err := goopenssl.Listen("tcp", "127.0.0.1:0", serverCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "gost-ok")
	})}
	defer server.Shutdown(context.Background())
	go server.Serve(listener)

	rt, err := newGOSTRoundTripper(pconfig.HTTPClientConfig{
		TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: true, ServerName: "localhost"},
	})
	if err != nil {
		t.Fatal(err)
	}
	standard := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	auto := &autoTLSRoundTripper{
		standard: standard,
		gost:     rt,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	client := &http.Client{Transport: auto, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "gost-ok" {
		t.Fatalf("body=%q", body)
	}
	if resp.TLS == nil || resp.TLS.CipherSuite == 0 {
		t.Fatalf("missing GOST TLS state: %#v", resp.TLS)
	}
}
