package openssl_test

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tarantool/go-openssl"
)

func sslConnect(t *testing.T, ssl_listener net.Listener) {
	for {
		var err error
		conn, err := ssl_listener.Accept()
		if err != nil {
			t.Errorf("failed accept: %s", err)
			continue
		}
		io.Copy(conn, io.LimitReader(rand.Reader, 1024))
		break
	}
}

func TestDial(t *testing.T) {
	ctx := openssl.GetCtx(t)
	defer ctx.Close()

	if err := ctx.SetCipherList("AES128-SHA"); err != nil {
		t.Fatal(err)
	}
	ssl_listener, err := openssl.Listen("tcp", "localhost:0", ctx)
	if err != nil {
		t.Fatal(err)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		sslConnect(t, ssl_listener)
		wg.Done()
	}()

	client, err := openssl.Dial(ssl_listener.Addr().Network(),
		ssl_listener.Addr().String(), ctx, openssl.InsecureSkipHostVerification)

	wg.Wait()

	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	n, err := io.Copy(io.Discard, io.LimitReader(client, 1024))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if n != 1024 {
		if n == 0 {
			t.Fatal("client is closed after creation")
		}
		t.Fatalf("client lost some bytes, expected %d, got %d", 1024, n)
	}
}

func TestDialTimeout(t *testing.T) {
	ctx := openssl.GetCtx(t)
	defer ctx.Close()

	if err := ctx.SetCipherList("AES128-SHA"); err != nil {
		t.Fatal(err)
	}
	ssl_listener, err := openssl.Listen("tcp", "localhost:0", ctx)
	if err != nil {
		t.Fatal(err)
	}

	client, err := openssl.DialTimeout(ssl_listener.Addr().Network(),
		ssl_listener.Addr().String(), time.Nanosecond, ctx, 0)

	if client != nil || err == nil {
		t.Fatalf("expected error")
	}
}

func TestDialContext(t *testing.T) {
	ctx := openssl.GetCtx(t)
	defer ctx.Close()

	if err := ctx.SetCipherList("AES128-SHA"); err != nil {
		t.Fatal(err)
	}
	ssl_listener, err := openssl.Listen("tcp", "localhost:0", ctx)
	if err != nil {
		t.Fatal(err)
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	client, err := openssl.DialContext(cancelCtx, ssl_listener.Addr().Network(),
		ssl_listener.Addr().String(), ctx, 0)

	if client != nil || err == nil {
		t.Fatalf("expected error")
	}
}
