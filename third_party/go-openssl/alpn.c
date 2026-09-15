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

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <string.h>

// Server-side ALPN selection.
//
// A Ctx that calls SetServerALPNProtos stores its ordered preference list, in
// ALPN wire format (a sequence of 1-byte-length-prefixed protocol names), in
// SSL_CTX ex_data under alpn_protos_idx. The buffer is heap-allocated and owned
// by OpenSSL: free_alpn_protos runs when the SSL_CTX itself is destroyed, so the
// list outlives every in-flight handshake that might read it. (Freeing it from a
// Go finalizer instead would be unsafe: the Go *Ctx can become unreachable while
// live SSL connections still hold a reference to the underlying SSL_CTX.)

// alpn_list is a ctx-owned server preference list. The length is stored
// alongside the bytes because SSL_select_next_proto needs server_len and the
// wire format is not self-delimiting.
struct alpn_list {
	unsigned int len;
	unsigned char data[];
};

static int alpn_protos_idx = -1;

static void free_alpn_protos(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                             int idx, long argl, void *argp) {
	OPENSSL_free(ptr);
}

// X_SSL_CTX_alpn_protos_new_index allocates (once) the SSL_CTX ex_data index
// used to store each ctx's server ALPN list. Called from Go package init.
int X_SSL_CTX_alpn_protos_new_index() {
	if (alpn_protos_idx < 0)
		alpn_protos_idx =
		    SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, free_alpn_protos);
	return alpn_protos_idx;
}

// X_alpn_select_cb is the server-side ALPN selection callback. It delegates the
// match to OpenSSL's SSL_select_next_proto against the current SSL_CTX's stored
// list, recovered from ex_data. SSL_get_SSL_CTX reflects any SNI-driven
// SSL_set_SSL_CTX swap, so each vhost's own list is used. On no overlap (or an
// invalid client list) it aborts the handshake with a no_application_protocol
// alert, as ALPN requires (RFC 7301).
static int X_alpn_select_cb(SSL *ssl, const unsigned char **out,
                            unsigned char *outlen, const unsigned char *in,
                            unsigned int inlen, void *arg) {
	struct alpn_list *al =
	    SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), alpn_protos_idx);
	if (al == NULL)
		return SSL_TLSEXT_ERR_ALERT_FATAL;

	// On a match SSL_select_next_proto points *out into al->data (the server
	// list) and favors the server's order; that pointer stays valid because al
	// lives for the SSL_CTX's lifetime, and OpenSSL copies the selected protocol
	// immediately after this callback returns.
	if (SSL_select_next_proto((unsigned char **)out, outlen, al->data, al->len,
	                          in, inlen) != OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}
	return SSL_TLSEXT_ERR_OK;
}

// X_SSL_CTX_set_server_alpn copies protos (wire format, protos_len bytes) into a
// ctx-owned buffer, replacing and freeing any list from a previous call, and
// registers the selection callback. Returns 1 on success, 0 on allocation
// failure.
int X_SSL_CTX_set_server_alpn(SSL_CTX *ctx, const unsigned char *protos,
                              unsigned int protos_len) {
	struct alpn_list *al = OPENSSL_malloc(sizeof(*al) + protos_len);
	if (al == NULL)
		return 0;
	al->len = protos_len;
	memcpy(al->data, protos, protos_len);

	// Install the new list before freeing the old one so the swap is atomic: if
	// SSL_CTX_set_ex_data fails, the ctx still points at the old (still-valid)
	// list and we free only the new allocation, leaving the ctx unchanged. On
	// success we free the previous list; the ex_data free function only runs on
	// ctx destruction, not on overwrite, and OPENSSL_free(NULL) is a no-op so the
	// first call is fine too. Freeing before a failed install would leave a
	// dangling pointer in the ctx (use-after-free at handshake, double-free at
	// ctx destruction).
	void *old = SSL_CTX_get_ex_data(ctx, alpn_protos_idx);
	if (!SSL_CTX_set_ex_data(ctx, alpn_protos_idx, al)) {
		OPENSSL_free(al);
		return 0;
	}
	OPENSSL_free(old);

	SSL_CTX_set_alpn_select_cb(ctx, X_alpn_select_cb, NULL);
	return 1;
}
