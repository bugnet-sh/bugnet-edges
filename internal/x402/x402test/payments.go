package x402test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	paymentsv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/payments/v1"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/payments/v1/paymentsv1connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The one network, asset and scheme the fake signs, as egress's prechecks pass them
const (
	solanaMainnet = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	usdcMint      = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
	schemeExact   = "exact"
)

const (
	// KeepFor is how long after signing the fake's keep_until falls, Payments' signed_payload_keep
	KeepFor = 45 * time.Second
	// BlockhashLife is how long the fake resends an unclean row's transaction
	BlockhashLife = 60 * time.Second
	// StartLeft is the allowance a new fake holds, $1.00
	StartLeft = 1_000_000
)

// Call is one call the fake received
type Call struct {
	Procedure  string
	ProtoMajor int
	// Client is the leaf certificate the caller presented
	Client *x509.Certificate
}

// ReserveFunc answers a ReserveAndSign in place of the default, which a nil answer and error keep
type ReserveFunc func(ctx context.Context, r *paymentsv1.ReserveAndSignRequest) (
	*paymentsv1.ReserveAndSignResponse, error)

// ReportFunc answers the nth ReportOutcome in place of the default, as ReserveFunc does
type ReportFunc func(ctx context.Context, n int, r *paymentsv1.ReportOutcomeRequest) (
	*paymentsv1.ReportOutcomeResponse, error)

// Payments is a fake X402SignerService over TLS 1.3 that requires egress's client certificate
type Payments struct {
	// URL is the base URL, set by Start
	URL string
	// TLS is the server's configuration, which a test may change before Start
	TLS *tls.Config

	t   testing.TB
	srv *httptest.Server

	mu          sync.Mutex
	calls       []Call
	reserves    []*paymentsv1.ReserveAndSignRequest
	reports     []*paymentsv1.ReportOutcomeRequest
	reportCalls int
	rows        []*row
	signings    int
	left        int64
	now         func() time.Time
	delay       time.Duration
	gate        chan struct{}
	onReserve   ReserveFunc
	onReport    ReportFunc
}

// row is one payment the fake signed
type row struct {
	id, ref, signature, payTo string
	amount                    int64
	placement, method, host   string
	target, body              []byte
	signedAt, keepUntil       time.Time
	clean                     bool
}

// NewPayments is a fake serving the CA's server pair and trusting its client pairs, not started
func NewPayments(t testing.TB, ca *CA) *Payments {
	t.Helper()
	p := &Payments{t: t, left: StartLeft, now: time.Now}
	p.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{ca.Server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.Pool(),
		NextProtos:   []string{"h2", "http/1.1"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 ||
				!slices.Contains(cs.PeerCertificates[0].DNSNames, ClientName) {
				return errors.New("x402test: the client certificate is not egress's")
			}
			return nil
		},
	}
	return p
}

// StartPayments starts a fake for the CA and closes it when the test ends
func StartPayments(t testing.TB, ca *CA) *Payments {
	t.Helper()
	p := NewPayments(t, ca)
	p.Start()
	return p
}

// Start serves on 127.0.0.1 with HTTP/2 and closes the fake when the test ends
func (p *Payments) Start() {
	path, h := paymentsv1connect.NewX402SignerServiceHandler(signer{p})
	mux := http.NewServeMux()
	mux.Handle(path, h)
	p.srv = httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			c := Call{Procedure: r.URL.Path, ProtoMajor: r.ProtoMajor}
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				c.Client = r.TLS.PeerCertificates[0]
			}
			p.mu.Lock()
			p.calls = append(p.calls, c)
			p.mu.Unlock()
			mux.ServeHTTP(w, r)
		}))
	p.srv.EnableHTTP2 = true
	p.srv.TLS = p.TLS
	p.srv.StartTLS()
	p.URL = p.srv.URL
	p.t.Cleanup(p.Close)
}

// Close lets every held call go and stops the server
func (p *Payments) Close() {
	p.Release()
	if p.srv != nil {
		p.srv.Close()
	}
}

// Calls lists every call received, in order
func (p *Payments) Calls() []Call {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.calls)
}

// Reserves lists every ReserveAndSign request received, in order
func (p *Payments) Reserves() []*paymentsv1.ReserveAndSignRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.reserves)
}

// Reports lists the ReportOutcome requests answered without an error, in order
func (p *Payments) Reports() []*paymentsv1.ReportOutcomeRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.reports)
}

// ReportCalls counts every ReportOutcome call, answered or not
func (p *Payments) ReportCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reportCalls
}

// Signings counts the fresh signatures, resends left out
func (p *Payments) Signings() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signings
}

// Left is the allowance left in micros
func (p *Payments) Left() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.left
}

// SetLeft sets the allowance left in micros
func (p *Payments) SetLeft(micros int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.left = micros
}

// SetClock sets the clock keep_until and the resend window count from
func (p *Payments) SetClock(now func() time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.now = now
}

// Delay holds every answer for d, or until the caller gives up
func (p *Payments) Delay(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.delay = d
}

// Hold stops every answer until Release, or until each caller gives up
func (p *Payments) Hold() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gate == nil {
		p.gate = make(chan struct{})
	}
}

// Release lets every held answer go
func (p *Payments) Release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gate != nil {
		close(p.gate)
		p.gate = nil
	}
}

// OnReserve answers ReserveAndSign with f while f is not nil
func (p *Payments) OnReserve(f ReserveFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onReserve = f
}

// OnReport answers ReportOutcome with f while f is not nil
func (p *Payments) OnReport(f ReportFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onReport = f
}

// RefConflict is Payments' answer to a report whose ref is not its row's
func RefConflict() error {
	err := connect.NewError(connect.CodeFailedPrecondition,
		errors.New("the ref is not the payment's"))
	d, derr := connect.NewErrorDetail(&errdetails.ErrorInfo{
		Reason: "REF_CONFLICT", Domain: "bugnet.payments",
	})
	if derr != nil {
		panic(derr)
	}
	err.AddDetail(d)
	return err
}

// PaymentSignature is the fake's fixed test format, read by the fake seller's in-memory settler
func PaymentSignature(accepted json.RawMessage, ref string) string {
	tx, err := json.Marshal("fake-" + ref)
	if err != nil {
		panic(err)
	}
	var b bytes.Buffer
	b.WriteString(`{"x402Version":2,"accepted":`)
	b.Write(accepted)
	b.WriteString(`,"payload":{"transaction":`)
	b.Write(tx)
	b.WriteString(`}}`)
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

// wait holds a call for the delay and the gate, an error once the caller gives up
func (p *Payments) wait(ctx context.Context) error {
	p.mu.Lock()
	d, gate := p.delay, p.gate
	p.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return connect.NewError(connect.CodeCanceled, ctx.Err())
		}
	}
	if d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			return connect.NewError(connect.CodeCanceled, ctx.Err())
		}
	}
	return nil
}

// signer serves the fake's two RPCs
type signer struct{ p *Payments }

func (s signer) ReserveAndSign(
	ctx context.Context, req *connect.Request[paymentsv1.ReserveAndSignRequest],
) (*connect.Response[paymentsv1.ReserveAndSignResponse], error) {
	p := s.p
	p.mu.Lock()
	p.reserves = append(p.reserves, proto.CloneOf(req.Msg))
	f := p.onReserve
	p.mu.Unlock()
	if err := p.wait(ctx); err != nil {
		return nil, err
	}
	if f != nil {
		res, err := f(ctx, req.Msg)
		if err != nil {
			return nil, err
		}
		if res != nil {
			return connect.NewResponse(res), nil
		}
	}
	return connect.NewResponse(p.sign(req.Msg)), nil
}

func (s signer) ReportOutcome(
	ctx context.Context, req *connect.Request[paymentsv1.ReportOutcomeRequest],
) (*connect.Response[paymentsv1.ReportOutcomeResponse], error) {
	p := s.p
	p.mu.Lock()
	p.reportCalls++
	n, f := p.reportCalls, p.onReport
	p.mu.Unlock()
	if err := p.wait(ctx); err != nil {
		return nil, err
	}
	if f != nil {
		res, err := f(ctx, n, req.Msg)
		if err != nil {
			return nil, err
		}
		if res != nil {
			p.mu.Lock()
			p.reports = append(p.reports, proto.CloneOf(req.Msg))
			p.mu.Unlock()
			return connect.NewResponse(res), nil
		}
	}
	res, err := p.report(req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

// sign answers a fresh signature, a resend of an unclean row with the same key, or a refusal
func (p *Payments) sign(r *paymentsv1.ReserveAndSignRequest) *paymentsv1.ReserveAndSignResponse {
	p.mu.Lock()
	defer p.mu.Unlock()
	accepted, amount, payTo, reason := choose(r.GetPaymentRequired())
	if reason != "" {
		refused := &paymentsv1.Refused{Reason: reason, AllowanceLeftMicros: p.left}
		return &paymentsv1.ReserveAndSignResponse{
			Result: &paymentsv1.ReserveAndSignResponse_Refused{Refused: refused},
		}
	}
	now := p.now()
	for _, w := range p.rows {
		if !w.clean && now.Before(w.signedAt.Add(BlockhashLife)) &&
			w.placement == r.GetPlacementId() && w.method == r.GetMethod() &&
			w.host == r.GetHost() && bytes.Equal(w.target, r.GetTargetSha256()) &&
			bytes.Equal(w.body, r.GetBodySha256()) {
			return p.signed(w, true)
		}
	}
	p.signings++
	w := &row{
		id: fmt.Sprintf("pay_%d", p.signings), ref: r.GetRef(),
		signature: PaymentSignature(accepted, r.GetRef()), payTo: payTo, amount: amount,
		placement: r.GetPlacementId(), method: r.GetMethod(), host: r.GetHost(),
		target: r.GetTargetSha256(), body: r.GetBodySha256(),
		signedAt: now, keepUntil: now.Add(KeepFor),
	}
	p.rows = append(p.rows, w)
	p.left -= amount
	return p.signed(w, false)
}

// signed is the Signed answer for w, with p.mu held
func (p *Payments) signed(w *row, resend bool) *paymentsv1.ReserveAndSignResponse {
	return &paymentsv1.ReserveAndSignResponse{Result: &paymentsv1.ReserveAndSignResponse_Signed{
		Signed: &paymentsv1.Signed{
			PaymentId: w.id, PaymentSignature: w.signature, AmountMicros: w.amount,
			PayTo: w.payTo, KeepUntil: timestamppb.New(w.keepUntil),
			AllowanceLeftMicros: p.left, Resend: resend, PaymentRef: w.ref,
		},
	}}
}

// report stores a hint, refusing a ref other than its row's, as Payments does
func (p *Payments) report(
	r *paymentsv1.ReportOutcomeRequest,
) (*paymentsv1.ReportOutcomeResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, w := range p.rows {
		if w.id != r.GetPaymentId() {
			continue
		}
		if w.ref != r.GetRef() {
			return nil, RefConflict()
		}
		if s := r.GetHttpStatus(); s >= 200 && s < 400 &&
			r.GetHint() == paymentsv1.SellerHint_SELLER_HINT_SUCCESS && !r.GetStreamCut() {
			w.clean = true
		}
	}
	p.reports = append(p.reports, proto.CloneOf(r))
	return &paymentsv1.ReportOutcomeResponse{AllowanceLeftMicros: p.left}, nil
}

// choose is the first exact Solana USDC entry of a v2 header, kept byte for byte, or a reason
func choose(header string) (accepted json.RawMessage, amount int64, payTo, reason string) {
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, 0, "", "not_x402"
	}
	var top struct {
		Version json.RawMessage   `json:"x402Version"`
		Accepts []json.RawMessage `json:"accepts"`
	}
	if json.Unmarshal(raw, &top) != nil {
		return nil, 0, "", "not_x402"
	}
	if string(top.Version) != "2" {
		return nil, 0, "", "version_unsupported"
	}
	for _, e := range top.Accepts {
		var f struct{ Scheme, Network, Asset, Amount, PayTo string }
		if json.Unmarshal(e, &f) != nil || f.Scheme != schemeExact ||
			f.Network != solanaMainnet || f.Asset != usdcMint {
			continue
		}
		n, err := strconv.ParseInt(f.Amount, 10, 64)
		if err != nil || n <= 0 {
			return nil, 0, "", "not_x402"
		}
		return e, n, f.PayTo, ""
	}
	return nil, 0, "", "network_unsupported"
}
