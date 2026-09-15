//go:build gost

// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0.

package prober

import (
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestShouldTryGOST(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{errors.New("tls: server selected unconfigured cipher suite"), true},
		{errors.New("remote error: tls: handshake failure"), true},
		{x509.UnknownAuthorityError{}, false},
		{errors.New("dial tcp: connection refused"), false},
		{errors.New("context deadline exceeded"), false},
	}
	for _, tc := range tests {
		if got := shouldTryGOST(tc.err); got != tc.want {
			t.Errorf("shouldTryGOST(%q) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestAutoTLSRoundTripperUsesStandardFirst(t *testing.T) {
	standardCalls, gostCalls := 0, 0
	standard := roundTripFunc(func(*http.Request) (*http.Response, error) {
		standardCalls++
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	gost := roundTripFunc(func(*http.Request) (*http.Response, error) {
		gostCalls++
		return nil, errors.New("must not be called")
	})
	rt := &autoTLSRoundTripper{standard: standard, gost: gost, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if standardCalls != 1 || gostCalls != 0 {
		t.Fatalf("standard calls=%d, GOST calls=%d", standardCalls, gostCalls)
	}
}

func TestAutoTLSRoundTripperFallsBackOnlyForTLSCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name        string
		standardErr error
		wantGOST    int
	}{
		{"cipher mismatch", errors.New("tls: server selected unconfigured cipher suite"), 1},
		{"certificate error", x509.UnknownAuthorityError{}, 0},
		{"network error", errors.New("connection refused"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gostCalls := 0
			standard := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, tc.standardErr })
			gost := roundTripFunc(func(*http.Request) (*http.Response, error) {
				gostCalls++
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
			})
			rt := &autoTLSRoundTripper{standard: standard, gost: gost, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			req, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
			_, _ = rt.RoundTrip(req)
			if gostCalls != tc.wantGOST {
				t.Fatalf("GOST calls=%d, want %d", gostCalls, tc.wantGOST)
			}
		})
	}
}
