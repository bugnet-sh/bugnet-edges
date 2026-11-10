package sshgw

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"golang.org/x/crypto/ssh"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeRouter is a SshGatewayService with the router's rules, kept in plain fields
type fakeRouter struct {
	routerv1connect.UnimplementedSshGatewayServiceHandler

	mu sync.Mutex
	// registered holds "alias|fingerprint" of each key a user added
	registered map[string]string // to the placement id
	deadline   map[string]time.Time
	removed    map[string]bool // "placement|fingerprint"
	ended      map[string]bool // placement ids
	leases     map[string]string
	maxSess    uint32
	maxFwd     uint32
	budget     *routerv1.EdgeBudget
	acquireErr error
	checkErr   error
	upstream   func(req *routerv1.OpenSshUpstreamRequest, placement string) (
		*routerv1.OpenSshUpstreamResponse, error)
	usage  []*routerv1.PlacementUsage
	events chan *routerv1.WatchSshEventsResponse

	authorizes, acquires, renews, releases, checks, upstreams int
	released                                                  []string
	// orderTP is the order_traceparent every AuthorizeSshKey answers
	orderTP string
	// traceparents holds the traceparent header of each call, by method name
	traceparents map[string][]string
}

// noteTrace records the traceparent a call carried, empty when it carried none
func (f *fakeRouter) noteTrace(method string, h http.Header) {
	if f.traceparents == nil {
		f.traceparents = map[string][]string{}
	}
	f.traceparents[method] = append(f.traceparents[method], h.Get("Traceparent"))
}

// carried is the traceparent headers the calls of method carried
func (f *fakeRouter) carried(method string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.traceparents[method]...)
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{
		registered: map[string]string{}, deadline: map[string]time.Time{},
		removed: map[string]bool{}, ended: map[string]bool{}, leases: map[string]string{},
		events: make(chan *routerv1.WatchSshEventsResponse, 32),
	}
}

func errInfo(code connect.Code, reason string) error {
	err := connect.NewError(code, errors.New("fake"))
	if d, derr := connect.NewErrorDetail(&errdetails.ErrorInfo{
		Reason: reason, Domain: routerDomain,
	}); derr == nil {
		err.AddDetail(d)
	}
	return err
}

func fingerprintOf(wire []byte) (string, error) {
	k, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(k), nil
}

// register lets key on alias, which belongs to placement and ends at deadline
func (f *fakeRouter) register(alias, placement string, key ssh.PublicKey, deadline time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registered[alias+"|"+ssh.FingerprintSHA256(key)] = placement
	f.deadline[placement] = deadline
}

func (f *fakeRouter) setDeadline(placement string, t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadline[placement] = t
}

func (f *fakeRouter) count(p *int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *p
}

func grantID(placement, fp string) string { return placement + "|" + fp }

func (f *fakeRouter) standing(placement string) (time.Time, bool) {
	d, ok := f.deadline[placement]
	return d, ok && !f.ended[placement] && time.Now().Before(d)
}

func (f *fakeRouter) AuthorizeSshKey(
	_ context.Context, req *connect.Request[routerv1.AuthorizeSshKeyRequest],
) (*connect.Response[routerv1.AuthorizeSshKeyResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authorizes++
	f.noteTrace("AuthorizeSshKey", req.Header())
	fp, err := fingerprintOf(req.Msg.GetPublicKey())
	if err != nil {
		return nil, errInfo(connect.CodeNotFound, "GRANT_UNKNOWN")
	}
	placement, ok := f.registered[req.Msg.GetAlias()+"|"+fp]
	if !ok || f.removed[placement+"|"+fp] {
		return nil, errInfo(connect.CodeNotFound, "GRANT_UNKNOWN")
	}
	d, ok := f.standing(placement)
	if !ok {
		return nil, errInfo(connect.CodeNotFound, "GRANT_UNKNOWN")
	}
	return connect.NewResponse(&routerv1.AuthorizeSshKeyResponse{
		GrantId: grantID(placement, fp), PlacementId: placement, Deadline: timestamppb.New(d),
		MaxSessions: f.maxSess, MaxForwards: f.maxFwd, OrderTraceparent: f.orderTP,
	}), nil
}

func (f *fakeRouter) AcquireSshConnection(
	_ context.Context, req *connect.Request[routerv1.AcquireSshConnectionRequest],
) (*connect.Response[routerv1.AcquireSshConnectionResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acquires++
	f.noteTrace("AcquireSshConnection", req.Header())
	if f.acquireErr != nil {
		return nil, f.acquireErr
	}
	id := fmt.Sprintf("lease-%d", f.acquires)
	f.leases[id] = req.Msg.GetGrantId()
	return connect.NewResponse(&routerv1.AcquireSshConnectionResponse{
		LeaseId: id, LeaseExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Budget: f.budget,
	}), nil
}

func (f *fakeRouter) RenewSshConnection(
	_ context.Context, _ *connect.Request[routerv1.RenewSshConnectionRequest],
) (*connect.Response[routerv1.RenewSshConnectionResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renews++
	return connect.NewResponse(&routerv1.RenewSshConnectionResponse{
		LeaseExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
	}), nil
}

func (f *fakeRouter) ReleaseSshConnection(
	_ context.Context, req *connect.Request[routerv1.ReleaseSshConnectionRequest],
) (*connect.Response[routerv1.ReleaseSshConnectionResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releases++
	f.noteTrace("ReleaseSshConnection", req.Header())
	f.released = append(f.released, req.Msg.GetLeaseId())
	delete(f.leases, req.Msg.GetLeaseId())
	return connect.NewResponse(&routerv1.ReleaseSshConnectionResponse{}), nil
}

func (f *fakeRouter) placementOf(grant string) string {
	for i := range grant {
		if grant[i] == '|' {
			return grant[:i]
		}
	}
	return grant
}

func (f *fakeRouter) OpenSshUpstream(
	_ context.Context, req *connect.Request[routerv1.OpenSshUpstreamRequest],
) (*connect.Response[routerv1.OpenSshUpstreamResponse], error) {
	f.mu.Lock()
	f.upstreams++
	f.noteTrace("OpenSshUpstream", req.Header())
	fn := f.upstream
	f.mu.Unlock()
	if fn == nil {
		return nil, errInfo(connect.CodeUnavailable, "SSH_PREPARING")
	}
	res, err := fn(req.Msg, f.placementOf(req.Msg.GetGrantId()))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (f *fakeRouter) CheckSshGrants(
	_ context.Context, req *connect.Request[routerv1.CheckSshGrantsRequest],
) (*connect.Response[routerv1.CheckSshGrantsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	if f.checkErr != nil {
		return nil, f.checkErr
	}
	out := map[string]*timestamppb.Timestamp{}
	for _, g := range req.Msg.GetGrantIds() {
		p := f.placementOf(g)
		if d, ok := f.standing(p); ok && !f.removed[g] {
			out[g] = timestamppb.New(d)
		}
	}
	return connect.NewResponse(&routerv1.CheckSshGrantsResponse{Deadlines: out}), nil
}

func (f *fakeRouter) ReportSshUsage(
	_ context.Context, req *connect.Request[routerv1.ReportSshUsageRequest],
) (*connect.Response[routerv1.ReportSshUsageResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usage = append(f.usage, req.Msg.GetUsage()...)
	return connect.NewResponse(&routerv1.ReportSshUsageResponse{}), nil
}

func (f *fakeRouter) WatchSshEvents(
	ctx context.Context, _ *connect.Request[routerv1.WatchSshEventsRequest],
	stream *connect.ServerStream[routerv1.WatchSshEventsResponse],
) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-f.events:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

// push sends an event to the gateway's stream
func (f *fakeRouter) push(ev *routerv1.EdgeEvent) {
	f.events <- &routerv1.WatchSshEventsResponse{Cursor: "c", Event: ev}
}

// serveRouter runs f behind an httptest server and answers a client of it
func serveRouter(t *testing.T, f *fakeRouter) routerv1connect.SshGatewayServiceClient {
	t.Helper()
	return serveRouterWith(t, f)
}

// serveRouterWith is serveRouter with Connect client options, such as the trace interceptor
func serveRouterWith(
	t *testing.T, f *fakeRouter, opts ...connect.ClientOption,
) routerv1connect.SshGatewayServiceClient {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(routerv1connect.NewSshGatewayServiceHandler(f))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return routerv1connect.NewSshGatewayServiceClient(srv.Client(), srv.URL, opts...)
}
