package inbound_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/assert"
)

func testInboundHTTP2(t *testing.T, inboundOptions inbound.HTTP2Option, outboundOptions outbound.Http2Option) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "http2_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	// Disable global auth behavior and related IP filtering for this test listener.
	if inboundOptions.Users == nil {
		inboundOptions.Users = inbound.AuthUsers{}
	}
	in, err := inbound.NewHTTP2(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions.Name = "http2_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.SkipCertVerify = true

	out, err := outbound.NewHttp2(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
}

func TestInboundHTTP2_TLS(t *testing.T) {
	inboundOptions := inbound.HTTP2Option{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	useTLS := true
	outboundOptions := outbound.Http2Option{
		TLS: &useTLS,
	}
	testInboundHTTP2(t, inboundOptions, outboundOptions)
}

func TestInboundHTTP2_H2C(t *testing.T) {
	inboundOptions := inbound.HTTP2Option{
		H2C: true,
	}
	outboundOptions := outbound.Http2Option{
		H2C: true,
		TLS: func() *bool { b := false; return &b }(),
	}
	testInboundHTTP2(t, inboundOptions, outboundOptions)
}

func TestInboundHTTP2_H2C_BadPreface(t *testing.T) {
	t.Parallel()
	inboundOptions := inbound.HTTP2Option{
		BaseOption: inbound.BaseOption{
			NameStr: "http2_inbound_h2c",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Users: inbound.AuthUsers{},
		H2C:   true,
	}
	in, err := inbound.NewHTTP2(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	c, err := net.Dial("tcp", in.Address())
	if !assert.NoError(t, err) {
		return
	}
	defer c.Close()

	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	b := make([]byte, 1)
	_, err = c.Read(b)
	assert.Error(t, err)
}
