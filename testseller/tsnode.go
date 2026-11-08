package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"

	"tailscale.com/tsnet"
)

// tsNode is a node on a real tailnet
type tsNode struct {
	srv  *tsnet.Server
	full string
}

// startTS joins the tailnet as host, keeping its key and certificates in stateDir
func startTS(ctx context.Context, host, stateDir, authKey string) (node, error) {
	srv := &tsnet.Server{
		Hostname:  host,
		Dir:       stateDir,
		AuthKey:   authKey,
		Ephemeral: false,
		Logf:      func(string, ...any) {},
	}
	if _, err := srv.Up(ctx); err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("node %s did not come up: %w", host, err)
	}
	domains := srv.CertDomains()
	if len(domains) == 0 {
		_ = srv.Close()
		return nil, fmt.Errorf("node %s has no certificate name, so HTTPS is not enabled", host)
	}
	return &tsNode{srv: srv, full: strings.TrimSuffix(domains[0], ".")}, nil
}

// listenFunnel listens for Funnel connections only, with the default TLS unless nextProtos is set
func (t *tsNode) listenFunnel(nextProtos []string) (net.Listener, error) {
	opts := []tsnet.FunnelOption{tsnet.FunnelOnly()}
	if len(nextProtos) > 0 {
		lc, err := t.srv.LocalClient()
		if err != nil {
			return nil, err
		}
		opts = append(opts, tsnet.FunnelTLSConfig(&tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: lc.GetCertificate,
			NextProtos:     nextProtos,
		}))
	}
	ln, err := t.srv.ListenFunnel("tcp", ":443", opts...)
	if err != nil {
		return nil, errors.Join(errors.New("this node cannot listen on Funnel"), err)
	}
	return ln, nil
}

func (t *tsNode) name() string { return t.full }

func (t *tsNode) close() error { return t.srv.Close() }
