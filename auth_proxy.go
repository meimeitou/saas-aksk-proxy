package saasakskproxy

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(AkSkMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("saas_aksk_proxy", parseCaddyfile)
}

type AkSkMiddleware struct {
	AcccessKey string `json:"access_key,omitempty"`
	SecretKey  string `json:"secret_key,omitempty"`
	s          *Signer
	logger     *zap.Logger
}

// CaddyModule返回Caddy模块的信息。
func (AkSkMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.saas_aksk_proxy",
		New: func() caddy.Module { return new(AkSkMiddleware) },
	}
}

// Provision实现了caddy.Provisioner。
func (m *AkSkMiddleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	m.s = &Signer{
		Key:    m.AcccessKey,
		Secret: m.SecretKey,
	}
	return nil
}

func (m *AkSkMiddleware) Validate() error {
	if m.AcccessKey == "" || m.SecretKey == "" {
		return fmt.Errorf("access_key or secret_key is empty")
	}
	return nil
}

func (m AkSkMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	m.s.Sign(r)
	m.logger.Debug("sign request", zap.String("auth", r.Header.Get(HeaderXAuthorization)))
	return next.ServeHTTP(w, r)
}

// parseCaddyfile从h中解读令牌到一个新的中间件。
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m AkSkMiddleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*AkSkMiddleware)(nil)
	_ caddy.Validator             = (*AkSkMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*AkSkMiddleware)(nil)
	_ caddyfile.Unmarshaler       = (*AkSkMiddleware)(nil)
)
