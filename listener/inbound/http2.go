package inbound

import (
	"errors"
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/http2"
	"github.com/metacubex/mihomo/log"
)

type HTTP2Option struct {
	BaseOption
	Users          AuthUsers     `inbound:"users,omitempty"`
	H2C            bool          `inbound:"h2c,omitempty"`
	Certificate    string        `inbound:"certificate,omitempty"`
	PrivateKey     string        `inbound:"private-key,omitempty"`
	ClientAuthType string        `inbound:"client-auth-type,omitempty"`
	ClientAuthCert string        `inbound:"client-auth-cert,omitempty"`
	EchKey         string        `inbound:"ech-key,omitempty"`
	RealityConfig  RealityConfig `inbound:"reality-config,omitempty"`
}

func (o HTTP2Option) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type HTTP2 struct {
	*Base
	config *HTTP2Option
	l      []*http2.Listener
}

func NewHTTP2(options *HTTP2Option) (*HTTP2, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &HTTP2{
		Base:   base,
		config: options,
	}, nil
}

func (h *HTTP2) Config() C.InboundConfig {
	return h.config
}

func (h *HTTP2) Address() string {
	var addrList []string
	for _, l := range h.l {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

func (h *HTTP2) Listen(tunnel C.Tunnel) error {
	for _, addr := range strings.Split(h.RawAddress(), ",") {
		l, err := http2.NewWithConfig(
			LC.AuthServer{
				Enable:         true,
				Listen:         addr,
				AuthStore:      h.config.Users.GetAuthStore(),
				Certificate:    h.config.Certificate,
				PrivateKey:     h.config.PrivateKey,
				ClientAuthType: h.config.ClientAuthType,
				ClientAuthCert: h.config.ClientAuthCert,
				EchKey:         h.config.EchKey,
				RealityConfig:  h.config.RealityConfig.Build(),
			},
			tunnel,
			h.config.H2C,
			h.Additions()...,
		)
		if err != nil {
			return err
		}
		h.l = append(h.l, l)
	}
	log.Infoln("HTTP2[%s] proxy listening at: %s", h.Name(), h.Address())
	return nil
}

func (h *HTTP2) Close() error {
	var errs []error
	for _, l := range h.l {
		err := l.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("close tcp listener %s err: %w", l.Address(), err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

var _ C.InboundListener = (*HTTP2)(nil)
