package saasakskproxy

import (
	"fmt"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// UnmarshalCaddyfile实现了caddyfile.Unmarshaler。
func (m *AkSkMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // skip args

	// handle nested blocks
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		fmt.Println("d.Val():", d.Val())
		switch d.Val() {
		case "access_key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.AcccessKey = d.Val()
		case "secret_key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.SecretKey = d.Val()
		}
	}
	return nil
}
