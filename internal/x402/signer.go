package x402

import (
	"context"
	"crypto"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"time"

	"connectrpc.com/connect"
	paymentsv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/payments/v1"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/payments/v1/paymentsv1connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
)

// The signer's log lines, which never hold a payload, ref, payTo or target
const (
	msgReserveFailed = "x402 reserve failed"
	msgReportRefused = "x402 report refused by Payments"
	msgReportDropped = "x402 report dropped after its tries"
	msgQueueFull     = "x402 report queue full, report dropped"
	msgCertExpiry    = "x402 client certificate expires soon"
)

const (
	// reportTries is how often one report is sent before it is dropped
	reportTries = 4
	// firstPause is the wait before a report's second try, doubled before each later one
	firstPause = 500 * time.Millisecond
	// maxAnswer bounds an answer from Payments, whose payload echoes a 402 of up to 32 KiB
	maxAnswer = 256 << 10
	// idleTimeout closes a connection to Payments that carried nothing for this long
	idleTimeout = 90 * time.Second
	// pingAfter checks a silent connection with a ping, so a dead Payments is noticed
	pingAfter   = 30 * time.Second
	pingTimeout = 15 * time.Second
)

// errBadAnswer is a ReserveAndSign answer egress cannot pay with, so it fails closed
var errBadAnswer = errors.New("x402: Payments answered neither a whole Signed nor a Refused")

// reasonShape is an ErrorInfo reason as Payments spells one
var reasonShape = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Signer calls Payments' X402SignerService over mutual TLS and queues outcome reports
type Signer struct {
	client             paymentsv1connect.X402SignerServiceClient
	serverName         string
	caFile, certFile   string
	key                crypto.Signer
	timeout, cleanWait time.Duration
	now                func() time.Time
	log                *slog.Logger
	queue              chan queued

	mu        sync.Mutex
	creds     creds
	transport *http.Transport
	pending   int

	// pause is the wait before a report's second try
	pause time.Duration
	// expiryTick stands in for Run's hourly ticker in tests
	expiryTick <-chan time.Time
	// lastExpiry is when Run last logged the expiry line
	lastExpiry time.Time
}

// queued is one report waiting for Run, with the tries already made
type queued struct {
	r     *paymentsv1.ReportOutcomeRequest
	tries int
}

// NewSigner loads the CA, the certificate and the key named by the credential under credDir
func NewSigner(
	s Settings, credDir string, log *slog.Logger, now func() time.Time,
) (*Signer, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if now == nil {
		now = time.Now
	}
	key, err := readKey(credDir, s.PaymentsClientKeyCredential)
	if err != nil {
		return nil, err
	}
	sg := &Signer{
		serverName: s.PaymentsServerName,
		caFile:     s.PaymentsCAFile,
		certFile:   s.PaymentsClientCertFile,
		key:        key,
		timeout:    time.Duration(s.PaymentsTimeout),
		cleanWait:  time.Duration(s.CleanReportWait),
		now:        now,
		log:        log,
		queue:      make(chan queued, s.ReportQueue),
		pause:      firstPause,
	}
	if sg.creds, err = sg.load(); err != nil {
		return nil, err
	}
	sg.transport = sg.newTransport()
	hc := &http.Client{
		Transport: latest{sg},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	sg.client = paymentsv1connect.NewX402SignerServiceClient(hc, s.PaymentsURL,
		connect.WithReadMaxBytes(maxAnswer))
	return sg, nil
}

// Reserve calls ReserveAndSign once under payments_timeout and never retries it
func (s *Signer) Reserve(
	ctx context.Context, r *paymentsv1.ReserveAndSignRequest,
) (*paymentsv1.ReserveAndSignResponse, error) {
	call, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	res, err := s.client.ReserveAndSign(call, connect.NewRequest(r))
	if err == nil && !whole(res.Msg) {
		err = errBadAnswer
	}
	if err != nil {
		// A caller that gave up is not a fault of Payments
		if ctx.Err() == nil {
			s.log.Warn(msgReserveFailed, failure(err)...)
		}
		return nil, err
	}
	return res.Msg, nil
}

// whole says res is a Refused, or a Signed with every field egress pays and reports with
func whole(res *paymentsv1.ReserveAndSignResponse) bool {
	if res.GetRefused() != nil {
		return true
	}
	sg := res.GetSigned()
	return sg != nil && sg.GetPaymentId() != "" && sg.GetPaymentSignature() != "" &&
		sg.GetPaymentRef() != "" && sg.GetAmountMicros() > 0
}

// Report queues a ReportOutcome, sent with up to 3 retries
func (s *Signer) Report(r *paymentsv1.ReportOutcomeRequest) {
	s.enqueue(queued{r: proto.CloneOf(r)})
}

// ReportClean sends a clean-end report first in line and waits at most clean_report_wait
func (s *Signer) ReportClean(
	ctx context.Context, r *paymentsv1.ReportOutcomeRequest,
) (left int64, ok bool) {
	r = proto.CloneOf(r)
	type result struct {
		left int64
		ok   bool
	}
	got := make(chan result, 1)
	go func() {
		// The report outlives the wait and the request, so it never races a later call
		left, err := s.call(context.WithoutCancel(ctx), r)
		got <- result{left, err == nil}
		switch {
		case err == nil:
		case final(err):
			s.log.Error(msgReportRefused, failure(err)...)
		default:
			s.enqueue(queued{r: r, tries: 1})
		}
	}()
	wait := time.NewTimer(s.cleanWait)
	defer wait.Stop()
	select {
	case res := <-got:
		return res.left, res.ok
	case <-wait.C:
	case <-ctx.Done():
	}
	return 0, false
}

// Run drains the report queue and logs the daily expiry line until ctx ends
func (s *Signer) Run(ctx context.Context) {
	tick := s.expiryTick
	if tick == nil {
		t := time.NewTicker(expiryEvery)
		defer t.Stop()
		tick = t.C
	}
	s.checkExpiry()
	for {
		select {
		case <-ctx.Done():
			return
		case q := <-s.queue:
			s.send(ctx, q)
		case <-tick:
			s.checkExpiry()
		}
	}
}

// enqueue holds a report for Run, dropping it when report_queue reports wait or are in flight
func (s *Signer) enqueue(q queued) {
	s.mu.Lock()
	if s.pending >= cap(s.queue) {
		s.mu.Unlock()
		s.log.Error(msgQueueFull, "report_queue", cap(s.queue))
		return
	}
	s.pending++
	s.mu.Unlock()
	s.queue <- q
}

// send tries one report until it lands, Payments refuses it or its tries run out
func (s *Signer) send(ctx context.Context, q queued) {
	defer func() {
		s.mu.Lock()
		s.pending--
		s.mu.Unlock()
	}()
	var err error
	for ; q.tries < reportTries; q.tries++ {
		if q.tries > 0 && !sleep(ctx, s.pause<<(q.tries-1)) {
			return
		}
		if _, err = s.call(ctx, q.r); err == nil {
			return
		}
		if final(err) {
			s.log.Error(msgReportRefused, failure(err)...)
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
	s.log.Error(msgReportDropped, append([]any{"tries", reportTries}, failure(err)...)...)
}

// call sends one ReportOutcome under payments_timeout
func (s *Signer) call(ctx context.Context, r *paymentsv1.ReportOutcomeRequest) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	res, err := s.client.ReportOutcome(ctx, connect.NewRequest(r))
	if err != nil {
		return 0, err
	}
	return res.Msg.GetAllowanceLeftMicros(), nil
}

// final says Payments refused a report for good, so a retry would only fire its alarm again
func final(err error) bool {
	code := connect.CodeOf(err)
	return code == connect.CodeFailedPrecondition || code == connect.CodeInvalidArgument ||
		code == connect.CodeNotFound
}

// failure is the log fields of a failed call, which never quote text Payments sent
func failure(err error) []any {
	attrs := []any{"code", connect.CodeOf(err).String()}
	if reason := reasonOf(err); reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	if !connect.IsWireError(err) {
		attrs = append(attrs, "err", err.Error())
	}
	return attrs
}

// reasonOf is the ErrorInfo reason of a Connect error, empty when it has none of the right shape
func reasonOf(err error) string {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return ""
	}
	for _, d := range ce.Details() {
		v, derr := d.Value()
		if info, ok := v.(*errdetails.ErrorInfo); ok && derr == nil &&
			reasonShape.MatchString(info.GetReason()) {
			return info.GetReason()
		}
	}
	return ""
}

// sleep waits d, false when ctx ends first
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
