package main

import (
	"context"
	"net"
)

// node is the part of a tsnet.Server the front end uses, faked in tests
type node interface {
	// listenFunnel listens on port 443 for Funnel connections only, offering nextProtos when set
	listenFunnel(nextProtos []string) (net.Listener, error)
	// name is the node's full ts.net name, from CertDomains
	name() string
	// close leaves the tailnet and keeps the state directory
	close() error
}

// newNode starts one node from its host name, state directory and auth key
type newNode func(ctx context.Context, host, stateDir, authKey string) (node, error)
