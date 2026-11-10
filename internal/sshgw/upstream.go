package sshgw

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/bugnet-sh/bugnet-edges/internal/telemetry"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/attr"
)

const (
	// subprotocol is the WebSocket subprotocol of the gate's SSH path
	subprotocol = "bugnet-ssh.v1"
	// readLimit is the largest WebSocket message the gateway reads from the gate
	readLimit = 1 << 20
	// handshakeWait bounds the SSH handshake with the sandbox's sshd
	handshakeWait = 10 * time.Second
)

var (
	errNoHostKey = errors.New("sshgw: the router sent no usable host key")
	errNoRoute   = errors.New("sshgw: the router sent no upstream transport")
)

// dialUpstream opens the SSH connection to placement's sshd as DP 9.4 describes
func (g *Gateway) dialUpstream(
	ctx context.Context, grant, placement string,
) (conn ssh.Conn, err error) {
	ctx, span := telemetry.Child(ctx, g.tracer, "ssh.upstream")
	defer func() { endUpstream(span, err) }()
	key := g.upstreamKey(placement)
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, g.upstreamWait)
	res, err := g.router.OpenSshUpstream(rctx, connect.NewRequest(&routerv1.OpenSshUpstreamRequest{
		GrantId: grant, GatewayPublicKey: signer.PublicKey().Marshal(),
	}))
	cancel()
	if err != nil {
		return nil, err
	}
	up := res.Msg
	span.SetAttributes(attr.Transport(transportName(up)))
	pinned, algos, err := parsePinned(up.GetHostKeys())
	if err != nil {
		return nil, err
	}
	nc, addr, err := g.transport(ctx, up)
	if err != nil {
		return nil, err
	}
	_ = nc.SetDeadline(time.Now().Add(handshakeWait))
	conn, chans, reqs, err := ssh.NewClientConn(nc, addr, &ssh.ClientConfig{
		User:              up.GetUser(),
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   pinned,
		HostKeyAlgorithms: algos,
	})
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	go rejectChannels(chans)
	go ssh.DiscardRequests(reqs)
	return conn, nil
}

// transport reaches the sandbox's sshd, through the gate's WebSocket or Boat's own TCP port
func (g *Gateway) transport(
	ctx context.Context, up *routerv1.OpenSshUpstreamResponse,
) (net.Conn, string, error) {
	switch t := up.GetTransport().(type) {
	case *routerv1.OpenSshUpstreamResponse_Websocket:
		w := t.Websocket
		dctx, cancel := context.WithTimeout(ctx, handshakeWait)
		defer cancel()
		c, _, err := websocket.Dial(dctx, w.GetUrl(), &websocket.DialOptions{
			HTTPHeader:   requestHeader(w),
			Subprotocols: []string{subprotocol},
		})
		if err != nil {
			return nil, "", err
		}
		c.SetReadLimit(readLimit)
		return websocket.NetConn(ctx, c, websocket.MessageBinary), w.GetUrl(), nil
	case *routerv1.OpenSshUpstreamResponse_Tcp:
		d := net.Dialer{Timeout: handshakeWait}
		nc, err := d.DialContext(ctx, "tcp", t.Tcp.GetAddress())
		return nc, t.Tcp.GetAddress(), err
	}
	return nil, "", errNoRoute
}

// requestHeader is the route's headers, with its cookies joined into one Cookie header
func requestHeader(w *routerv1.WebSocketUpstream) http.Header {
	h := http.Header{}
	for _, v := range w.GetHeaders() {
		h.Add(v.GetName(), v.GetValue())
	}
	var cookies []string
	for _, v := range w.GetCookies() {
		cookies = append(cookies, v.GetName()+"="+v.GetValue())
	}
	if len(cookies) > 0 {
		h.Add("Cookie", strings.Join(cookies, "; "))
	}
	return h
}

// parsePinned accepts a host key that matches one of lines, and lists the algorithms to offer
func parsePinned(lines []string) (ssh.HostKeyCallback, []string, error) {
	var keys []ssh.PublicKey
	var algos []string
	for _, l := range lines {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err != nil {
			continue
		}
		keys = append(keys, k)
		for _, a := range hostAlgorithms(k) {
			if !slices.Contains(algos, a) {
				algos = append(algos, a)
			}
		}
	}
	if len(keys) == 0 {
		return nil, nil, errNoHostKey
	}
	check := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		for _, k := range keys {
			if bytes.Equal(k.Marshal(), key.Marshal()) {
				return nil
			}
		}
		return errors.New("sshgw: the sandbox's host key is not the pinned one")
	}
	return check, algos, nil
}

// hostAlgorithms maps a pinned RSA key to its SHA-2 signatures, never ssh-rsa
func hostAlgorithms(k ssh.PublicKey) []string {
	if k.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{k.Type()}
}

// dialReason names the class of an upstream failure for the log, never the error's own text
func dialReason(err error) string {
	switch {
	case errors.Is(err, errNoHostKey):
		return "no_host_key"
	case errors.Is(err, errNoRoute):
		return "no_route"
	case connect.CodeOf(err) != connect.CodeUnknown:
		if r := reasonOf(err); r != "" {
			return strings.ToLower(r)
		}
		return "router_" + connect.CodeOf(err).String()
	}
	return "connect_failed"
}
