package outbound

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/net/http2"
)

type Http2 struct {
	*Base
	user      string
	pass      string
	tlsConfig *tls.Config
	option    *Http2Option

	clientOnce sync.Once
	client     *http.Client
}

type Http2Option struct {
	BasicOption
	Name           string            `proxy:"name"`
	Server         string            `proxy:"server"`
	Port           int               `proxy:"port"`
	UserName       string            `proxy:"username,omitempty"`
	Password       string            `proxy:"password,omitempty"`
	TLS            *bool             `proxy:"tls,omitempty"`
	H2C            bool              `proxy:"h2c,omitempty"`
	SNI            string            `proxy:"sni,omitempty"`
	SkipCertVerify bool              `proxy:"skip-cert-verify,omitempty"`
	Fingerprint    string            `proxy:"fingerprint,omitempty"`
	Certificate    string            `proxy:"certificate,omitempty"`
	PrivateKey     string            `proxy:"private-key,omitempty"`
	Headers        map[string]string `proxy:"headers,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (h *Http2) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	client := h.getClient()

	pr, pw := io.Pipe()
	req := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: h.proxyScheme(),
			Host:   h.addr,
		},
		Host:       metadata.RemoteAddress(),
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     make(http.Header),
		Body:       pr,
	}

	req.Header.Set("User-Agent", "Go-http-client/2.0")
	for k, v := range h.option.Headers {
		req.Header.Set(k, v)
	}

	if h.user != "" && h.pass != "" {
		auth := h.user + ":" + h.pass
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	baseCtx := ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	reqCtx, cancel := context.WithCancel(baseCtx)
	defer func() {
		if err != nil {
			cancel()
		}
	}()

	resp, err := client.Do(req.WithContext(reqCtx))
	if err != nil {
		_ = pw.Close()
		_ = pr.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.Close()
		_ = pr.Close()
		return nil, fmt.Errorf("HTTP/2 CONNECT proxy error: %s", resp.Status)
	}

	c1, c2 := N.Pipe()

	closeOnce := sync.Once{}
	closeAll := func() {
		closeOnce.Do(func() {
			cancel()
			_ = c1.Close()
			_ = c2.Close()
			_ = resp.Body.Close()
			_ = pw.Close()
			_ = pr.Close()
		})
	}

	go func() {
		_, _ = io.Copy(pw, c2)
		closeAll()
	}()
	go func() {
		_, _ = io.Copy(c2, resp.Body)
		closeAll()
	}()

	return NewConn(c1, h), nil
}

// ProxyInfo implements C.ProxyAdapter
func (h *Http2) ProxyInfo() C.ProxyInfo {
	info := h.Base.ProxyInfo()
	info.DialerProxy = h.option.DialerProxy
	return info
}

func (h *Http2) Close() error {
	if h.client != nil {
		if tr, ok := h.client.Transport.(interface{ CloseIdleConnections() }); ok {
			tr.CloseIdleConnections()
		}
	}
	return nil
}

func (h *Http2) proxyScheme() string {
	if h.option.H2C || h.tlsConfig == nil {
		return "http"
	}
	return "https"
}

func (h *Http2) getClient() *http.Client {
	h.clientOnce.Do(func() {
		connectTimeout := C.DefaultTCPTimeout

		tr := &http2.Transport{
			IdleConnTimeout: 30 * time.Second,
		}
		if h.option.H2C || h.tlsConfig == nil {
			tr.AllowHTTP = true
			tr.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
				defer cancel()
				return h.dialer.DialContext(dialCtx, network, addr)
			}
		} else {
			tr.TLSClientConfig = h.tlsConfig
			tr.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				if cfg == nil {
					cfg = h.tlsConfig
				}
				dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
				defer cancel()
				conn, err := h.dialer.DialContext(dialCtx, network, addr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(conn, cfg)
				if err := tlsConn.HandshakeContext(dialCtx); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return tlsConn, nil
			}
		}
		h.client = &http.Client{
			Transport: tr,
		}
	})
	return h.client
}

func NewHttp2(option Http2Option) (*Http2, error) {
	var tlsConfig *tls.Config

	useTLS := true
	if option.H2C {
		useTLS = false
	} else if option.TLS != nil {
		useTLS = *option.TLS
	}

	if useTLS {
		sni := option.Server
		if option.SNI != "" {
			sni = option.SNI
		}
		var err error
		tlsConfig, err = ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: option.SkipCertVerify,
				ServerName:         sni,
			},
			Fingerprint: option.Fingerprint,
			Certificate: option.Certificate,
			PrivateKey:  option.PrivateKey,
		})
		if err != nil {
			return nil, err
		}
	}

	outbound := &Http2{
		Base: &Base{
			name:   option.Name,
			addr:   net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:     C.Http2,
			pdName: option.ProviderName,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		user:      option.UserName,
		pass:      option.Password,
		tlsConfig: tlsConfig,
		option:    &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
