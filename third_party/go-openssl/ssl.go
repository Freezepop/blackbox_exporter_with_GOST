// Copyright (C) 2017. See AUTHORS.
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

// #include "shim.h"
import "C"

import (
	"os"
	"runtime"
	"unsafe"

	"github.com/mattn/go-pointer"
)

type SSLTLSExtErr int

const (
	SSLTLSExtErrOK           SSLTLSExtErr = C.SSL_TLSEXT_ERR_OK
	SSLTLSExtErrAlertWarning SSLTLSExtErr = C.SSL_TLSEXT_ERR_ALERT_WARNING
	SSLTLSEXTErrAlertFatal   SSLTLSExtErr = C.SSL_TLSEXT_ERR_ALERT_FATAL
	SSLTLSEXTErrNoAck        SSLTLSExtErr = C.SSL_TLSEXT_ERR_NOACK
)

var (
	ssl_idx = C.X_SSL_new_index()
)

//export get_ssl_idx
func get_ssl_idx() C.int {
	return ssl_idx
}

type SSL struct {
	ssl       *C.SSL
	verify_cb VerifyCallback
}

//export go_ssl_verify_cb_thunk
func go_ssl_verify_cb_thunk(p unsafe.Pointer, ok C.int, ctx *C.X509_STORE_CTX) C.int {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: verify callback panic'd: %v", err)
			os.Exit(1)
		}
	}()
	verify_cb := pointer.Restore(p).(*SSL).verify_cb
	// set up defaults just in case verify_cb is nil
	if verify_cb != nil {
		store := &CertificateStoreCtx{ctx: ctx}
		if verify_cb(ok == 1, store) {
			ok = 1
		} else {
			ok = 0
		}
	}
	return ok
}

// Wrapper around SSL_get_servername. Returns server name according to rfc6066
// http://tools.ietf.org/html/rfc6066.
func (s *SSL) GetServername() string {
	return C.GoString(C.SSL_get_servername(s.ssl, C.TLSEXT_NAMETYPE_host_name))
}

// GetALPNNegotiated returns the application protocol selected via ALPN during
// the handshake, or "" if none was negotiated (the peer offered no ALPN, or the
// two sides shared no protocol). It is only meaningful after the handshake has
// completed, and works on both client and server connections. This is how a
// server reads the result of SetServerALPNProtos selection. Wraps
// SSL_get0_alpn_selected.
func (s *SSL) GetALPNNegotiated() string {
	var data *C.uchar
	var length C.uint
	C.SSL_get0_alpn_selected(s.ssl, &data, &length)
	if length == 0 {
		return ""
	}
	return C.GoStringN((*C.char)(unsafe.Pointer(data)), C.int(length))
}

// GetOptions returns SSL options. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
func (s *SSL) GetOptions() Options {
	return Options(C.X_SSL_get_options(s.ssl))
}

// SetOptions sets SSL options. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
func (s *SSL) SetOptions(options Options) Options {
	return Options(C.X_SSL_set_options(s.ssl, C.long(options)))
}

// ClearOptions clear SSL options. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
func (s *SSL) ClearOptions(options Options) Options {
	return Options(C.X_SSL_clear_options(s.ssl, C.long(options)))
}

// EnableTracing enables TLS handshake tracing using openssls
// SSL_trace function. If useStderr is false, stdout is used.
// https://www.openssl.org/docs/manmaster/man3/SSL_trace.html
func (s *SSL) EnableTracing(useStderr bool) {
	output := C.stdout
	if useStderr {
		output = C.stderr
	}

	C.X_SSL_toggle_tracing(s.ssl, output, 1)
}

// DisableTracing unsets the msg callback from EnableTracing.
func (s *SSL) DisableTracing() {
	C.X_SSL_toggle_tracing(s.ssl, nil, 0)
}

// SetVerify controls peer verification settings. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) SetVerify(options VerifyOptions, verify_cb VerifyCallback) {
	s.verify_cb = verify_cb
	if verify_cb != nil {
		C.SSL_set_verify(s.ssl, C.int(options), (*[0]byte)(C.X_SSL_verify_cb))
	} else {
		C.SSL_set_verify(s.ssl, C.int(options), nil)
	}
}

// SetVerifyMode controls peer verification setting. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) SetVerifyMode(options VerifyOptions) {
	s.SetVerify(options, s.verify_cb)
}

// SetVerifyCallback controls peer verification setting. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) SetVerifyCallback(verify_cb VerifyCallback) {
	s.SetVerify(s.VerifyMode(), verify_cb)
}

// GetVerifyCallback returns callback function. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) GetVerifyCallback() VerifyCallback {
	return s.verify_cb
}

// VerifyMode returns peer verification setting. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) VerifyMode() VerifyOptions {
	return VerifyOptions(C.SSL_get_verify_mode(s.ssl))
}

// SetVerifyDepth controls how many certificates deep the certificate
// verification logic is willing to follow a certificate chain. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) SetVerifyDepth(depth int) {
	C.SSL_set_verify_depth(s.ssl, C.int(depth))
}

// GetVerifyDepth controls how many certificates deep the certificate
// verification logic is willing to follow a certificate chain. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (s *SSL) GetVerifyDepth() int {
	return int(C.SSL_get_verify_depth(s.ssl))
}

// SetSSLCtx changes context to new one. Useful for Server Name Indication (SNI)
// rfc6066 http://tools.ietf.org/html/rfc6066. See
// http://stackoverflow.com/questions/22373332/serving-multiple-domains-in-one-box-with-sni
func (s *SSL) SetSSLCtx(ctx *Ctx) {
	/*
	 * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
	 * adjust other things we care about
	 */
	C.SSL_set_SSL_CTX(s.ssl, ctx.ctx)
}

// GetVersion() returns the name of the protocol used for the connection. It
// should only be called after the initial handshake has been completed otherwise
// the result may be unreliable.
// https://www.openssl.org/docs/man1.0.2/man3/SSL_get_version.html
func (s *SSL) GetVersion() string {
	return C.GoString(C.SSL_get_version(s.ssl))
}

// DaneEnable enables DANE validation for this connection. It must be called
// before the TLS handshake.
// https://www.openssl.org/docs/man1.1.1/man3/SSL_dane_clear_flags.html
func (s *SSL) DaneEnable(tlsaBaseDomain string) error {
	tlsaBaseDomainCString := C.CString(tlsaBaseDomain)
	defer C.free(unsafe.Pointer(tlsaBaseDomainCString))

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if C.SSL_dane_enable(s.ssl, tlsaBaseDomainCString) <= 0 {
		return errorFromErrorQueue()
	}

	return nil
}

// DaneTlsaAdd loads a TLSA record that will be validated against the presented certificate.
// Data must be in wire form, not hex ASCII. If all TLSA records you try to add are unusable
// (bool return value) an opportunistic application must disable peer authentication by
// using a verify mode equal to VerifyNone.
// https://www.openssl.org/docs/man1.1.1/man3/SSL_dane_clear_flags.html
func (s *SSL) DaneTlsaAdd(usage, selector, matchingType byte, data []byte) (bool, error) {
	cData := C.CBytes(data)
	defer C.free(cData)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if status := C.SSL_dane_tlsa_add(
		s.ssl,
		C.uchar(usage),
		C.uchar(selector),
		C.uchar(matchingType),
		(*C.uchar)(cData),
		C.size_t(len(data)),
	); status < 0 {
		return false, errorFromErrorQueue()
	} else if status == 0 {
		return false, nil
	}
	return true, nil
}

// DaneGet0DaneAuthority returns a value that is negative if DANE verification failed (or
// was not enabled), 0 if an EE TLSA record directly matched the leaf certificate, or a
// positive number indicating the depth at which a TA record matched an issuer certificate.
// However, the depth doesn't refer to the list of certificates as sent by the peer but rather
// how it's returned from SSL_get0_verified_chain.
// https://www.openssl.org/docs/man1.1.1/man3/SSL_dane_clear_flags.html
func (s *SSL) DaneGet0DaneAuthority() int {
	return int(C.SSL_get0_dane_authority(s.ssl, nil, nil))
}

// DaneSetFlags enables given flags for this connection. Returns previous flags.
// https://www.openssl.org/docs/man1.1.1/man3/SSL_dane_clear_flags.html
func (s *SSL) DaneSetFlags(flags DaneFlags) DaneFlags {
	return DaneFlags(C.SSL_dane_set_flags(s.ssl, C.ulong(flags)))
}

// DaneClearFlags disables flags set by DaneSetFlags. Returns previous flags.
func (s *SSL) DaneClearFlags(flags DaneFlags) DaneFlags {
	return DaneFlags(C.SSL_dane_clear_flags(s.ssl, C.ulong(flags)))
}

//export sni_cb_thunk
func sni_cb_thunk(p unsafe.Pointer, con *C.SSL, ad unsafe.Pointer, arg unsafe.Pointer) C.int {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: verify callback sni panic'd: %v", err)
			os.Exit(1)
		}
	}()

	sni_cb := pointer.Restore(p).(*Ctx).sni_cb

	s := &SSL{ssl: con}
	// This attaches a pointer to our SSL struct into the SNI callback.
	C.SSL_set_ex_data(s.ssl, get_ssl_idx(), pointer.Save(s))

	// Note: this is ctx.sni_cb, not C.sni_cb
	return C.int(sni_cb(s))
}
