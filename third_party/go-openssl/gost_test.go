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

//go:build openssl_gost
// +build openssl_gost

package openssl_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-openssl"
)

func TestGostCipherRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		cipher    string
		plaintext string
	}{
		{"GOST28147", "GOST 28147-89", "The GOST cipher round-trip test"},
		{"Kuznyechik", "kuznyechik-cbc", "Kuznyechik block cipher round-trip test"},
		{"Magma", "magma-cbc", "Magma block cipher round-trip test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := openssl.GetCipherByName(tt.cipher)
			require.NoError(t, err)
			require.NotNil(t, cipher)

			key := bytes.Repeat([]byte{0x01}, cipher.KeySize())
			iv := bytes.Repeat([]byte{0x02}, cipher.IVSize())
			plaintext := []byte(tt.plaintext)

			encCtx, err := openssl.NewEncryptionCipherCtx(cipher, nil, key, iv)
			require.NoError(t, err)

			ciphertext, err := encCtx.EncryptUpdate(plaintext)
			require.NoError(t, err)

			final, err := encCtx.EncryptFinal()
			require.NoError(t, err)
			ciphertext = append(ciphertext, final...)

			decCtx, err := openssl.NewDecryptionCipherCtx(cipher, nil, key, iv)
			require.NoError(t, err)

			decrypted, err := decCtx.DecryptUpdate(ciphertext)
			require.NoError(t, err)

			finalDec, err := decCtx.DecryptFinal()
			require.NoError(t, err)
			decrypted = append(decrypted, finalDec...)

			require.Equal(t, plaintext, decrypted)
		})
	}
}

func TestLoadPrivateKeyFromPEM_GOST(t *testing.T) {
	keyPath := filepath.Join("testdata", "gost", "client.key")

	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	key, err := openssl.LoadPrivateKeyFromPEM(keyPEM)
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestNewCtxFromFiles_GOST(t *testing.T) {
	ctx, err := openssl.NewCtxFromFiles(
		filepath.Join("testdata", "gost", "client.crt"),
		filepath.Join("testdata", "gost", "client.key"),
	)
	require.NoError(t, err)
	ctx.Close()
}
