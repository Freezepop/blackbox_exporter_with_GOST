//go:build !gost

// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0.

package prober

import (
	"log/slog"
	"net/http"

	pconfig "github.com/prometheus/common/config"
)

// wrapGOSTFallback keeps regular builds behavior-compatible with upstream.
func wrapGOSTFallback(standard http.RoundTripper, _ pconfig.HTTPClientConfig, _ *slog.Logger) (http.RoundTripper, error) {
	return standard, nil
}
