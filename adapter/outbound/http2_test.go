package outbound

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestHttp2Outbound_H2(t *testing.T) {
	const target = "example.com:80"

	type seen struct {
		method             string
		host               string
		proxyAuthorization string
		headerXTest        string
		userAgent          string
	}
	seenCh := make(chan seen, 1)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- seen{
			method:             r.Method,
			host:               r.Host,
			proxyAuthorization: r.Header.Get("Proxy-Authorization"),
			headerXTest:        r.Header.Get("X-Test"),
			userAgent:          r.Header.Get("User-Agent"),
		}

		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.Copy(flushWriter{w}, r.Body)
	})

	ts := httptest.NewUnstartedServer(handler)
	ts.EnableHTTP2 = true
	_ = http2.ConfigureServer(ts.Config, &http2.Server{})
	ts.StartTLS()
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	useTLS := true
	proxy, err := NewHttp2(Http2Option{
		BasicOption:    BasicOption{},
		Name:           "http2",
		Server:         host,
		Port:           port,
		TLS:            &useTLS,
		SkipCertVerify: true,
		UserName:       "u",
		Password:       "p",
		Headers: map[string]string{
			"X-Test": "1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	md := &C.Metadata{}
	if err := md.SetRemoteAddress(target); err != nil {
		t.Fatal(err)
	}

	conn, err := proxy.DialContext(context.Background(), md)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello")
	if _, err := conn.Write(payload); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if string(buf) != string(payload) {
		_ = conn.Close()
		t.Fatalf("unexpected echo: got %q want %q", string(buf), string(payload))
	}
	_ = conn.Close()

	select {
	case s := <-seenCh:
		if s.method != http.MethodConnect {
			t.Fatalf("unexpected method: got %q want %q", s.method, http.MethodConnect)
		}
		if s.host != target {
			t.Fatalf("unexpected host: got %q want %q", s.host, target)
		}
		if s.proxyAuthorization == "" {
			t.Fatalf("missing Proxy-Authorization header")
		}
		if s.headerXTest != "1" {
			t.Fatalf("unexpected X-Test header: got %q want %q", s.headerXTest, "1")
		}
		if s.userAgent == "" {
			t.Fatalf("missing User-Agent header")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for CONNECT request")
	}
}

func TestHttp2Outbound_H2C(t *testing.T) {
	const target = "example.com:80"

	seenCh := make(chan string, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- r.Proto
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.Copy(flushWriter{w}, r.Body)
	})

	ts := httptest.NewServer(h2c.NewHandler(handler, &http2.Server{}))
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := NewHttp2(Http2Option{
		BasicOption: BasicOption{},
		Name:        "http2-h2c",
		Server:      host,
		Port:        port,
		H2C:         true,
	})
	if err != nil {
		t.Fatal(err)
	}

	md := &C.Metadata{}
	if err := md.SetRemoteAddress(target); err != nil {
		t.Fatal(err)
	}

	conn, err := proxy.DialContext(context.Background(), md)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := []byte("hello")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("unexpected echo: got %q want %q", string(buf), string(payload))
	}

	select {
	case proto := <-seenCh:
		if proto != "HTTP/2.0" {
			t.Fatalf("unexpected proto: got %q want %q", proto, "HTTP/2.0")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for h2c CONNECT request")
	}
}

type flushWriter struct {
	w http.ResponseWriter
}

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}
