package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	dialTimeout   = 10 * time.Second
	dnsTimeout    = 4 * time.Second
	ownRefresh    = time.Minute
	maxDialedIPs  = 4
	dnsPacketSize = 1232
)

var (
	errRefused  = errors.New("egress: the address is not one the proxy may reach")
	errNoAnswer = errors.New("egress: the name has no usable address")
)

// refused lists the ranges DP 10.5 step 7 closes, with the other ranges no public host lives in
var refused = prefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	"::/96", "2001::/32", "2002::/16", "64:ff9b::/96", "64:ff9b:1::/48", "fc00::/7", "fe80::/10",
	"ff00::/8",
)

func prefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Refused says whether the proxy may never connect to ip, whatever name led to it
func Refused(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return true
	}
	for _, p := range refused {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Dialer connects to public hosts only, resolving through its own resolvers
type Dialer struct {
	resolvers []string
	next      atomic.Uint64
	now       func() time.Time

	mu       sync.Mutex
	own      map[netip.Addr]bool
	ownAt    time.Time
	ownAddrs func() ([]net.Addr, error)
	// upstream maps a host to the address to dial for it, set only by a localrun build
	upstream func(host string) (string, bool)
}

// NewDialer resolves through resolvers, each a host and port, and never through the local files
func NewDialer(resolvers []string) *Dialer {
	return &Dialer{resolvers: resolvers, now: time.Now, ownAddrs: net.InterfaceAddrs}
}

// DialContext connects to addr, a host and port, refusing every address Refused names
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if to, ok := d.upstreamFor(host); ok {
		var dl net.Dialer
		return dl.DialContext(ctx, network, to)
	}
	var ips []netip.Addr
	if ip, perr := netip.ParseAddr(host); perr == nil {
		ips = []netip.Addr{ip}
	} else if ips, err = d.lookup(ctx, host); err != nil {
		return nil, err
	}
	var errs []error
	tried := 0
	for _, ip := range ips {
		if d.refuses(ip) {
			errs = append(errs, errRefused)
			continue
		}
		if tried++; tried > maxDialedIPs {
			break
		}
		dl := net.Dialer{Timeout: dialTimeout, Control: d.control}
		c, err := dl.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil, errNoAnswer
	}
	return nil, errors.Join(errs...)
}

func (d *Dialer) upstreamFor(host string) (string, bool) {
	if d.upstream == nil {
		return "", false
	}
	return d.upstream(host)
}

// control is the last check, run on the address the kernel is about to connect to
func (d *Dialer) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || d.refuses(ap.Addr()) {
		return errRefused
	}
	return nil
}

func (d *Dialer) refuses(ip netip.Addr) bool {
	return Refused(ip) || d.isOwn(ip.Unmap())
}

// isOwn says whether ip is an address of this host, read again every minute
func (d *Dialer) isOwn(ip netip.Addr) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.own == nil || d.now().Sub(d.ownAt) > ownRefresh {
		d.own = map[netip.Addr]bool{}
		d.ownAt = d.now()
		addrs, _ := d.ownAddrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					d.own[ip.Unmap()] = true
				}
			}
		}
	}
	return d.own[ip]
}

/* Resolving */

// lookup returns the addresses of name from the resolvers, IPv4 first
func (d *Dialer) lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	if len(d.resolvers) == 0 {
		return nil, errors.New("egress: no resolvers")
	}
	var v4, v6 []netip.Addr
	var errs []error
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		got, err := d.ask(ctx, name, t)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if t == dnsmessage.TypeA {
			v4 = got
		} else {
			v6 = got
		}
	}
	out := append(v4, v6...)
	if len(out) == 0 {
		if len(errs) > 0 {
			return nil, errors.Join(errs...)
		}
		return nil, errNoAnswer
	}
	return out, nil
}

// ask sends one question to each resolver in turn, starting from a rotating one
func (d *Dialer) ask(ctx context.Context, name string, t dnsmessage.Type) ([]netip.Addr, error) {
	start := int(d.next.Add(1))
	var errs []error
	for i := range d.resolvers {
		r := d.resolvers[(start+i)%len(d.resolvers)]
		got, err := query(ctx, r, name, t)
		if err == nil {
			return got, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func query(ctx context.Context, resolver, name string, t dnsmessage.Type) ([]netip.Addr, error) {
	dn, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, err
	}
	id := uint16(rand.Uint32())
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dn, Type: t, Class: dnsmessage.ClassINET}},
	}
	wire, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	reply, err := exchange(ctx, "udp", resolver, wire)
	if err == nil {
		var p dnsmessage.Parser
		if h, perr := p.Start(reply); perr == nil && h.Truncated {
			reply, err = exchange(ctx, "tcp", resolver, wire)
		}
	}
	if err != nil {
		return nil, err
	}
	return answers(reply, id, t)
}

func exchange(ctx context.Context, network, resolver string, wire []byte) ([]byte, error) {
	var dl net.Dialer
	c, err := dl.DialContext(ctx, network, resolver)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if dead, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dead)
	}
	if network == "tcp" {
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
		if _, err := c.Write(append(framed, wire...)); err != nil {
			return nil, err
		}
		var n [2]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return nil, err
		}
		buf := make([]byte, binary.BigEndian.Uint16(n[:]))
		_, err := io.ReadFull(c, buf)
		return buf, err
	}
	if _, err := c.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, dnsPacketSize*4)
	n, err := c.Read(buf)
	return buf[:n], err
}

// answers reads the address records of a reply to the question with id
func answers(reply []byte, id uint16, t dnsmessage.Type) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil {
		return nil, err
	}
	if h.ID != id || !h.Response {
		return nil, errors.New("egress: the resolver's reply does not answer the question")
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("egress: the resolver answered code %d", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var out []netip.Addr
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		switch {
		case rh.Type == dnsmessage.TypeA && t == dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, err
			}
			out = append(out, netip.AddrFrom4(r.A))
		case rh.Type == dnsmessage.TypeAAAA && t == dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, err
			}
			out = append(out, netip.AddrFrom16(r.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
		}
	}
}
