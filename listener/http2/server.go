package http2

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/ntp"
	"golang.org/x/net/http2"
)

type Listener struct {
	listener net.Listener
	addr     string
	closed   bool
	h2c      bool
}

// RawAddress implements C.Listener
func (l *Listener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *Listener) Address() string {
	return l.listener.Addr().String()
}

// Close implements C.Listener
func (l *Listener) Close() error {
	l.closed = true
	return l.listener.Close()
}

func New(addr string, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	return NewWithConfig(LC.AuthServer{Enable: true, Listen: addr, AuthStore: authStore.Default}, tunnel, false, additions...)
}

func NewWithConfig(config LC.AuthServer, tunnel C.Tunnel, h2c bool, additions ...inbound.Addition) (*Listener, error) {
	isDefault := false
	if len(additions) == 0 {
		isDefault = true
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-HTTP2"),
			inbound.WithSpecialRules(""),
		}
	}

	ln, err := inbound.Listen("tcp", config.Listen)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tlsC.Config{Time: ntp.Now}
	tlsConfig.NextProtos = []string{"h2"}
	var realityBuilder *reality.Builder

	if config.Certificate != "" && config.PrivateKey != "" {
		cert, err := ca.LoadTLSKeyPair(config.Certificate, config.PrivateKey, C.Path)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tlsC.Certificate{tlsC.UCertificate(cert)}

		if config.EchKey != "" {
			err = ech.LoadECHKey(config.EchKey, tlsConfig, C.Path)
			if err != nil {
				return nil, err
			}
		}
	}
	tlsConfig.ClientAuth = tlsC.ClientAuthTypeFromString(config.ClientAuthType)
	if len(config.ClientAuthCert) > 0 {
		if tlsConfig.ClientAuth == tlsC.NoClientCert {
			tlsConfig.ClientAuth = tlsC.RequireAndVerifyClientCert
		}
	}
	if tlsConfig.ClientAuth == tlsC.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tlsC.RequireAndVerifyClientCert {
		pool, err := ca.LoadCertificates(config.ClientAuthCert, C.Path)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
	}
	if config.RealityConfig.PrivateKey != "" {
		if len(tlsConfig.Certificates) > 0 {
			return nil, errors.New("certificate is unavailable in reality")
		}
		if tlsConfig.ClientAuth != tlsC.NoClientCert {
			return nil, errors.New("client-auth is unavailable in reality")
		}
		realityBuilder, err = config.RealityConfig.Build(tunnel)
		if err != nil {
			return nil, err
		}
	}

	if h2c && (realityBuilder != nil || len(tlsConfig.Certificates) > 0) {
		return nil, errors.New("h2c is incompatible with tls/reality")
	}

	if realityBuilder != nil {
		ln = realityBuilder.NewListener(ln)
	} else if len(tlsConfig.Certificates) > 0 {
		ln = tlsC.NewListener(ln, tlsConfig)
	}

	hl := &Listener{
		listener: ln,
		addr:     config.Listen,
		h2c:      h2c,
	}

	go hl.serve(tunnel, config.AuthStore, isDefault, additions)

	return hl, nil
}

type connInfoKey struct{}

type connInfo struct {
	srcConn   net.Conn
	tunnel    C.Tunnel
	store     auth.AuthStore
	additions []inbound.Addition
}

func (l *Listener) serve(tunnel C.Tunnel, store auth.AuthStore, isDefault bool, additions []inbound.Addition) {
	h2Server := &http2.Server{}
	handler := http.HandlerFunc(serveHTTP2Proxy)

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if l.closed {
				return
			}
			continue
		}

		connStore := store
		if isDefault || connStore == authStore.Default { // only apply on default listener
			if !inbound.IsRemoteAddrDisAllowed(conn.RemoteAddr()) {
				_ = conn.Close()
				continue
			}
			if inbound.SkipAuthRemoteAddr(conn.RemoteAddr()) {
				connStore = authStore.Nil
			}
		}

		go func(srcConn net.Conn) {
			defer srcConn.Close()

			info := &connInfo{
				srcConn:   srcConn,
				tunnel:    tunnel,
				store:     connStore,
				additions: additions,
			}

			// h2c: prior-knowledge only (client sends HTTP/2 preface directly).
			opts := &http2.ServeConnOpts{
				Handler: handler,
				Context: context.WithValue(context.Background(), connInfoKey{}, info),
			}

			if l.h2c {
				const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
				_ = srcConn.SetReadDeadline(time.Now().Add(2 * time.Second))
				var buf [len(preface)]byte
				_, err := io.ReadFull(srcConn, buf[:])
				_ = srcConn.SetReadDeadline(time.Time{})
				if err != nil || string(buf[:]) != preface {
					return
				}
				opts.SawClientPreface = true
			}

			h2Server.ServeConn(srcConn, opts)
		}(conn)
	}
}

func serveHTTP2Proxy(w http.ResponseWriter, r *http.Request) {
	ci, ok := r.Context().Value(connInfoKey{}).(*connInfo)
	if !ok || ci == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	user, ok := authenticate(w, r, ci.store.Authenticator())
	if !ok {
		return
	}

	additions := append([]inbound.Addition(nil), ci.additions...)
	additions = append(additions, inbound.WithInUser(user))

	if r.Method != http.MethodConnect {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authority := strings.TrimSpace(r.Host)
	if authority == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	req := r
	if req.URL == nil {
		req.URL = &url.URL{}
	}
	if _, _, err := net.SplitHostPort(authority); err != nil {
		authority = net.JoinHostPort(strings.Trim(authority, "[]"), "443")
	}
	req.URL.Host = authority
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	c1, c2 := N.Pipe()
	proxyConn := &addrConn{
		Conn:  c1,
		laddr: ci.srcConn.LocalAddr(),
		raddr: ci.srcConn.RemoteAddr(),
	}

	closeOnce := sync.Once{}
	closeAll := func() {
		closeOnce.Do(func() {
			_ = c1.Close()
			_ = c2.Close()
			_ = r.Body.Close()
		})
	}
	defer closeAll()

	go func() {
		_, _ = io.Copy(c2, r.Body)
		closeAll()
	}()
	go func() {
		_, _ = io.Copy(flushWriter{w: w}, c2)
		closeAll()
	}()
	go func() {
		<-r.Context().Done()
		closeAll()
	}()

	ci.tunnel.HandleTCPConn(inbound.NewHTTPS(req, proxyConn, additions...))
}

type addrConn struct {
	net.Conn
	laddr net.Addr
	raddr net.Addr
}

func (c *addrConn) LocalAddr() net.Addr  { return c.laddr }
func (c *addrConn) RemoteAddr() net.Addr { return c.raddr }

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

func authenticate(w http.ResponseWriter, request *http.Request, authenticator auth.Authenticator) (user string, ok bool) {
	credential := parseBasicProxyAuthorization(request)
	if credential == "" && authenticator != nil {
		w.Header().Set("Proxy-Authenticate", "Basic")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return "", false
	}
	user, pass, err := decodeBasicProxyAuthorization(credential)
	authed := authenticator == nil || (err == nil && authenticator.Verify(user, pass))
	if !authed {
		return user, false
	}
	return user, true
}

func parseBasicProxyAuthorization(request *http.Request) string {
	value := request.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return ""
	}
	return value[len(prefix):]
}

func decodeBasicProxyAuthorization(credential string) (string, string, error) {
	plain, err := base64.StdEncoding.DecodeString(credential)
	if err != nil {
		return "", "", err
	}
	user, pass, found := strings.Cut(string(plain), ":")
	if !found {
		return "", "", errors.New("invalid login")
	}
	return user, pass, nil
}
