package x402

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/bugnet-sh/bugnet-edges/internal/settings"
	"github.com/bugnet-sh/bugnet-edges/internal/x402/x402test"
	paymentsv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/payments/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
)

// testPayTo is a base58 address of 32 bytes
const testPayTo = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"

// logBuf collects JSON log lines for assertions
type logBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// records lists the records whose msg is msg, each as its decoded attributes
func (l *logBuf) records(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// waitFor polls cond every 5 ms for up to 2 s
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// idle waits until no report waits for Run or is in flight
func idle(t *testing.T, s *Signer) {
	t.Helper()
	waitFor(t, "an empty queue", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.pending == 0
	})
}

// signerEnv is a dev layout on disk, a fake Payments trusting its CA and the settings for both
type signerEnv struct {
	ca   *x402test.CA
	dir  string
	fake *x402test.Payments
	s    Settings
	logs *logBuf
}

// newSignerEnv starts a fake Payments for a fresh dev layout
func newSignerEnv(t *testing.T) *signerEnv {
	t.Helper()
	e := &signerEnv{ca: x402test.NewCA(t), dir: t.TempDir(), logs: &logBuf{}}
	e.ca.WriteDev(t, e.dir)
	e.fake = x402test.StartPayments(t, e.ca)
	e.s = devSettings(e.dir, e.fake.URL)
	return e
}

// devSettings points egress at url with the dev layout in dir and short waits
func devSettings(dir, url string) Settings {
	s := Defaults()
	s.PaymentsURL = url
	s.PaymentsCAFile = filepath.Join(dir, x402test.CAFile)
	s.PaymentsClientCertFile = filepath.Join(dir, x402test.ClientCertFile)
	s.PaymentsTimeout = settings.Duration(2 * time.Second)
	s.CleanReportWait = settings.Duration(time.Second)
	return s
}

func (e *signerEnv) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// signer builds a Signer on the real clock with 1 ms between report tries
func (e *signerEnv) signer(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner(e.s, e.dir, e.logger(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	s.pause = time.Millisecond
	return s
}

// run drains s's queue until the test ends
func run(t *testing.T, s *Signer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// required is a v2 header with one exact USDC entry of amount micros
func required(amount int64) string {
	return EncodeRequired(Required{Version: 2, Accepts: []Entry{{
		Scheme: "exact", Network: SolanaMainnet, Asset: USDCMint, PayTo: testPayTo,
		AmountMicros: amount, AmountOK: true,
	}}}, "https://api.example.com/v1/x", nil)
}

// reserveRequest is a request for a $0.001 call with ref
func reserveRequest(ref string) *paymentsv1.ReserveAndSignRequest {
	body := sha256.Sum256([]byte("{}"))
	target := sha256.Sum256([]byte("pl_a\x00/v1/x?q=weather"))
	return &paymentsv1.ReserveAndSignRequest{
		AccountId: "so_1", PlacementId: "pl_a", Ref: ref, ServiceId: "xs_aaaaaaaaaaaaaaaa",
		Method: "POST", Host: "api.example.com", Path: "/v1/x", BodySha256: body[:],
		PaymentRequired: required(1000), TargetSha256: target[:],
	}
}

// report is a clean report of a payment
func report(id, ref string) *paymentsv1.ReportOutcomeRequest {
	return &paymentsv1.ReportOutcomeRequest{
		PaymentId: id, Ref: ref, HttpStatus: 200, Hint: paymentsv1.SellerHint_SELLER_HINT_SUCCESS,
	}
}

func reserveOK(t *testing.T, s *Signer, ref string) *paymentsv1.Signed {
	t.Helper()
	res, err := s.Reserve(context.Background(), reserveRequest(ref))
	if err != nil {
		t.Fatal(err)
	}
	if res.GetSigned() == nil {
		t.Fatalf("not signed: %v", res)
	}
	return res.GetSigned()
}

func TestSignerMutualTLS(t *testing.T) {
	e := newSignerEnv(t)
	s := e.signer(t)
	signed := reserveOK(t, s, "aaaaaaaaaaaaaaaa")
	eq(t, signed.GetPaymentRef(), "aaaaaaaaaaaaaaaa")
	eq(t, signed.GetAmountMicros(), int64(1000))
	calls := e.fake.Calls()
	eq(t, len(calls), 1)
	eq(t, calls[0].Procedure, "/bugnet.payments.v1.X402SignerService/ReserveAndSign")
	eq(t, calls[0].ProtoMajor, 2)
	eq(t, calls[0].Client.DNSNames, []string{x402test.ClientName})
	eq(t, len(e.fake.Reserves()), 1)
	eq(t, proto.Equal(e.fake.Reserves()[0], reserveRequest("aaaaaaaaaaaaaaaa")), true)
}

// failedVerify is the server check that failed a call, nil when none did
func failedVerify(err error) *tls.CertificateVerificationError {
	var v *tls.CertificateVerificationError
	if errors.As(err, &v) {
		return v
	}
	return nil
}

func TestSignerRefusesOtherServerName(t *testing.T) {
	e := newSignerEnv(t)
	other := x402test.NewPayments(t, e.ca)
	key := x402test.NewKey(t)
	pem := e.ca.Issue(t, &key.PublicKey, "other.internal", x509.ExtKeyUsageServerAuth,
		time.Now().AddDate(1, 0, 0))
	other.TLS.Certificates = []tls.Certificate{x402test.Pair(t, pem, key)}
	other.Start()
	e.s.PaymentsURL = other.URL
	_, err := e.signer(t).Reserve(context.Background(), reserveRequest("aaaaaaaaaaaaaaaa"))
	v := failedVerify(err)
	if v == nil {
		t.Fatalf("got %v, want a failed server check", err)
	}
	var name x509.HostnameError
	eq(t, errors.As(v.Err, &name), true)
	eq(t, len(other.Calls()), 0)
}

func TestSignerRefusesOtherCA(t *testing.T) {
	e := newSignerEnv(t)
	other := x402test.NewPayments(t, e.ca)
	other.TLS.Certificates = []tls.Certificate{x402test.NewCA(t).Server}
	other.Start()
	e.s.PaymentsURL = other.URL
	_, err := e.signer(t).Reserve(context.Background(), reserveRequest("aaaaaaaaaaaaaaaa"))
	v := failedVerify(err)
	if v == nil {
		t.Fatalf("got %v, want a failed server check", err)
	}
	var unknown x509.UnknownAuthorityError
	eq(t, errors.As(v.Err, &unknown), true)
	eq(t, len(other.Calls()), 0)
}

func TestSignerTLS13Only(t *testing.T) {
	e := newSignerEnv(t)
	old := x402test.NewPayments(t, e.ca)
	old.TLS.MinVersion, old.TLS.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	old.Start()
	e.s.PaymentsURL = old.URL
	_, err := e.signer(t).Reserve(context.Background(), reserveRequest("aaaaaaaaaaaaaaaa"))
	if err == nil || !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("got %v, want a protocol version failure", err)
	}
	eq(t, len(old.Calls()), 0)
}

func TestReserveDeadline(t *testing.T) {
	e := newSignerEnv(t)
	e.s.PaymentsTimeout = settings.Duration(200 * time.Millisecond)
	s := e.signer(t)
	e.fake.Delay(time.Second)
	start := time.Now()
	_, err := s.Reserve(context.Background(), reserveRequest("aaaaaaaaaaaaaaaa"))
	took := time.Since(start)
	eq(t, connect.CodeOf(err), connect.CodeDeadlineExceeded)
	if took > 300*time.Millisecond {
		t.Fatalf("Reserve took %v", took)
	}
	eq(t, len(e.fake.Reserves()), 1)
	eq(t, len(e.fake.Calls()), 1)
	recs := e.logs.records(t, msgReserveFailed)
	eq(t, len(recs), 1)
	eq(t, recs[0]["level"], any("WARN"))
	eq(t, recs[0]["code"], any("deadline_exceeded"))
}

func TestReserveQuietWhenTheCallerLeaves(t *testing.T) {
	for _, tc := range []struct {
		name string
		code connect.Code
		ctx  func() (context.Context, context.CancelFunc)
	}{
		{"cancelled", connect.CodeCanceled, func() (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		}},
		{"its own deadline", connect.CodeDeadlineExceeded,
			func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 100*time.Millisecond)
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSignerEnv(t)
			s := e.signer(t)
			e.fake.Hold()
			ctx, cancel := tc.ctx()
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := s.Reserve(ctx, reserveRequest("aaaaaaaaaaaaaaaa"))
				done <- err
			}()
			waitFor(t, "the held reserve", func() bool { return len(e.fake.Reserves()) == 1 })
			if tc.code == connect.CodeCanceled {
				cancel()
			}
			select {
			case err := <-done:
				eq(t, connect.CodeOf(err), tc.code)
			case <-time.After(2 * time.Second):
				t.Fatal("Reserve outlived its caller")
			}
			eq(t, len(e.logs.records(t, msgReserveFailed)), 0)
		})
	}
}

func TestReserveAcceptsAResendOfAnotherRef(t *testing.T) {
	e := newSignerEnv(t)
	s := e.signer(t)
	first := reserveOK(t, s, "aaaaaaaaaaaaaaaa")
	again := reserveOK(t, s, "bbbbbbbbbbbbbbbb")
	eq(t, again.GetResend(), true)
	eq(t, again.GetPaymentId(), first.GetPaymentId())
	eq(t, again.GetPaymentRef(), "aaaaaaaaaaaaaaaa")
}

func TestReservePassesARefusal(t *testing.T) {
	e := newSignerEnv(t)
	refused := &paymentsv1.Refused{
		Reason: "allowance_spent", AskedMicros: 10000, MaxMicros: 10000, AllowanceLeftMicros: 3,
	}
	e.fake.OnReserve(func(context.Context, *paymentsv1.ReserveAndSignRequest) (
		*paymentsv1.ReserveAndSignResponse, error,
	) {
		return &paymentsv1.ReserveAndSignResponse{
			Result: &paymentsv1.ReserveAndSignResponse_Refused{Refused: refused},
		}, nil
	})
	res, err := e.signer(t).Reserve(context.Background(), reserveRequest("aaaaaaaaaaaaaaaa"))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, proto.Equal(res.GetRefused(), refused), true)
}

func TestReserveFailsClosed(t *testing.T) {
	good := func() *paymentsv1.Signed {
		return &paymentsv1.Signed{
			PaymentId: "pay_1", PaymentSignature: "c2ln", AmountMicros: 1000,
			PayTo: testPayTo, PaymentRef: "aaaaaaaaaaaaaaaa",
		}
	}
	for name, signed := range map[string]func(*paymentsv1.Signed){
		"no payment_id":         func(s *paymentsv1.Signed) { s.PaymentId = "" },
		"no payment_signature":  func(s *paymentsv1.Signed) { s.PaymentSignature = "" },
		"no payment_ref":        func(s *paymentsv1.Signed) { s.PaymentRef = "" },
		"no amount":             func(s *paymentsv1.Signed) { s.AmountMicros = 0 },
		"a negative amount":     func(s *paymentsv1.Signed) { s.AmountMicros = -1 },
		"neither signed nor no": nil,
	} {
		t.Run(name, func(t *testing.T) {
			e := newSignerEnv(t)
			res := &paymentsv1.ReserveAndSignResponse{}
			if signed != nil {
				s := good()
				signed(s)
				res.Result = &paymentsv1.ReserveAndSignResponse_Signed{Signed: s}
			}
			e.fake.OnReserve(func(context.Context, *paymentsv1.ReserveAndSignRequest) (
				*paymentsv1.ReserveAndSignResponse, error,
			) {
				return res, nil
			})
			got, err := e.signer(t).Reserve(context.Background(),
				reserveRequest("aaaaaaaaaaaaaaaa"))
			if err == nil || got != nil {
				t.Fatalf("got %v and %v, want only an error", got, err)
			}
		})
	}
}

func TestReportRetriedThreeTimes(t *testing.T) {
	e := newSignerEnv(t)
	s := e.signer(t)
	run(t, s)
	signed := reserveOK(t, s, "aaaaaaaaaaaaaaaa")
	fails := 3
	e.fake.OnReport(func(_ context.Context, n int, _ *paymentsv1.ReportOutcomeRequest) (
		*paymentsv1.ReportOutcomeResponse, error,
	) {
		if n <= fails {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("restarting"))
		}
		return nil, nil
	})
	s.Report(report(signed.GetPaymentId(), signed.GetPaymentRef()))
	waitFor(t, "the report", func() bool { return len(e.fake.Reports()) == 1 })
	eq(t, e.fake.ReportCalls(), 4)
	eq(t, len(e.logs.records(t, msgReportDropped)), 0)

	fails = 1 << 30
	e.fake.OnReport(func(context.Context, int, *paymentsv1.ReportOutcomeRequest) (
		*paymentsv1.ReportOutcomeResponse, error,
	) {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("restarting"))
	})
	s.Report(report(signed.GetPaymentId(), signed.GetPaymentRef()))
	waitFor(t, "the drop", func() bool { return len(e.logs.records(t, msgReportDropped)) == 1 })
	eq(t, e.fake.ReportCalls(), 8)
	eq(t, len(e.fake.Reports()), 1)
	rec := e.logs.records(t, msgReportDropped)[0]
	eq(t, rec["level"], "ERROR")
	eq(t, rec["code"], "unavailable")
}

func TestReportRefConflictNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name, code, reason string
		answer             func(*testing.T, *Signer) *paymentsv1.ReportOutcomeRequest
		hook               x402test.ReportFunc
	}{
		{
			name: "ref_conflict", code: "failed_precondition", reason: "REF_CONFLICT",
			answer: func(t *testing.T, s *Signer) *paymentsv1.ReportOutcomeRequest {
				signed := reserveOK(t, s, "aaaaaaaaaaaaaaaa")
				return report(signed.GetPaymentId(), "bbbbbbbbbbbbbbbb")
			},
		},
		{
			name: "invalid_argument", code: "invalid_argument",
			answer: func(*testing.T, *Signer) *paymentsv1.ReportOutcomeRequest {
				return report("pay_9", "x")
			},
			hook: func(context.Context, int, *paymentsv1.ReportOutcomeRequest) (
				*paymentsv1.ReportOutcomeResponse, error,
			) {
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad hint_tx"))
			},
		},
		{
			name: "unknown payment_id", code: "not_found", answer: anyReport,
			hook: func(context.Context, int, *paymentsv1.ReportOutcomeRequest) (
				*paymentsv1.ReportOutcomeResponse, error,
			) {
				return nil, connect.NewError(connect.CodeNotFound, errors.New("no such payment"))
			},
		},
		{
			name: "a reason of 64", code: "failed_precondition", reason: strings.Repeat("R", 64),
			answer: anyReport, hook: refuseWith(strings.Repeat("R", 64)),
		},
		{
			name: "a lower case reason", code: "failed_precondition",
			answer: anyReport, hook: refuseWith("ref_conflict"),
		},
		{
			name: "a reason over 64", code: "failed_precondition",
			answer: anyReport, hook: refuseWith(strings.Repeat("R", 65)),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSignerEnv(t)
			s := e.signer(t)
			run(t, s)
			e.fake.OnReport(tc.hook)
			s.Report(tc.answer(t, s))
			waitFor(t, "the refusal line", func() bool {
				return len(e.logs.records(t, msgReportRefused)) == 1
			})
			eq(t, e.fake.ReportCalls(), 1)
			eq(t, len(e.fake.Reports()), 0)
			rec := e.logs.records(t, msgReportRefused)[0]
			eq(t, rec["code"], any(tc.code))
			reason, has := rec["reason"]
			if tc.reason == "" && has {
				t.Fatalf("logged the reason %q, which is not shaped as Payments spells one", reason)
			}
			if tc.reason != "" {
				eq(t, reason, any(tc.reason))
			}
			eq(t, len(e.logs.records(t, msgReportDropped)), 0)
		})
	}
}

func TestReportQueueFull(t *testing.T) {
	e := newSignerEnv(t)
	e.s.ReportQueue = 2
	s := e.signer(t)
	run(t, s)
	e.fake.Hold()
	s.Report(report("pay_1", "aaaaaaaaaaaaaaaa"))
	waitFor(t, "the first report in flight", func() bool { return e.fake.ReportCalls() == 1 })
	s.Report(report("pay_2", "bbbbbbbbbbbbbbbb"))
	eq(t, len(e.logs.records(t, msgQueueFull)), 0)
	s.Report(report("pay_3", "cccccccccccccccc"))
	eq(t, len(e.logs.records(t, msgQueueFull)), 1)
	e.fake.Release()
	waitFor(t, "two reports", func() bool { return len(e.fake.Reports()) == 2 })
	got := e.fake.Reports()
	eq(t, []string{got[0].GetPaymentId(), got[1].GetPaymentId()}, []string{"pay_1", "pay_2"})
	s.Report(report("pay_4", "dddddddddddddddd"))
	waitFor(t, "room again", func() bool { return len(e.fake.Reports()) == 3 })
	eq(t, len(e.logs.records(t, msgQueueFull)), 1)
}

func TestReportCleanWaitsAtMostCleanReportWait(t *testing.T) {
	e := newSignerEnv(t)
	e.s.CleanReportWait = settings.Duration(100 * time.Millisecond)
	s := e.signer(t)
	signed := reserveOK(t, s, "aaaaaaaaaaaaaaaa")
	e.fake.Delay(300 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	left, ok := s.ReportClean(ctx, report(signed.GetPaymentId(), signed.GetPaymentRef()))
	took := time.Since(start)
	// The code may leave once its last byte is written, and the report must still land
	cancel()
	eq(t, ok, false)
	eq(t, left, int64(0))
	if took < 90*time.Millisecond || took > 250*time.Millisecond {
		t.Fatalf("ReportClean took %v", took)
	}
	waitFor(t, "the late report", func() bool { return len(e.fake.Reports()) == 1 })
	eq(t, e.fake.ReportCalls(), 1)
}

func TestReportCleanAnswersLeft(t *testing.T) {
	e := newSignerEnv(t)
	s := e.signer(t)
	signed := reserveOK(t, s, "aaaaaaaaaaaaaaaa")
	e.fake.SetLeft(4321)
	left, ok := s.ReportClean(context.Background(),
		report(signed.GetPaymentId(), signed.GetPaymentRef()))
	eq(t, ok, true)
	eq(t, left, int64(4321))
	eq(t, len(e.fake.Reports()), 1)
}

func TestReportCleanSkipsTheQueue(t *testing.T) {
	e := newSignerEnv(t)
	s := e.signer(t)
	run(t, s)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	e.fake.OnReport(func(ctx context.Context, _ int, r *paymentsv1.ReportOutcomeRequest) (
		*paymentsv1.ReportOutcomeResponse, error,
	) {
		if r.GetPaymentId() == "pay_slow" {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return nil, nil
	})
	for range 3 {
		s.Report(report("pay_slow", "aaaaaaaaaaaaaaaa"))
	}
	waitFor(t, "a slow report in flight", func() bool { return e.fake.ReportCalls() == 1 })
	start := time.Now()
	_, ok := s.ReportClean(context.Background(), report("pay_clean", "bbbbbbbbbbbbbbbb"))
	eq(t, ok, true)
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("ReportClean took %v behind the queue", took)
	}
	got := e.fake.Reports()
	eq(t, len(got), 1)
	eq(t, got[0].GetPaymentId(), "pay_clean")
}

func TestReportCleanFailureRetriedFromTheQueue(t *testing.T) {
	e := newSignerEnv(t)
	s := e.signer(t)
	run(t, s)
	e.fake.OnReport(func(_ context.Context, n int, _ *paymentsv1.ReportOutcomeRequest) (
		*paymentsv1.ReportOutcomeResponse, error,
	) {
		if n == 1 {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("restarting"))
		}
		return nil, nil
	})
	_, ok := s.ReportClean(context.Background(), report("pay_1", "aaaaaaaaaaaaaaaa"))
	eq(t, ok, false)
	waitFor(t, "the retried report", func() bool { return len(e.fake.Reports()) == 1 })
	eq(t, e.fake.ReportCalls(), 2)
}

func TestReportCleanRefusalNotRetried(t *testing.T) {
	e := newSignerEnv(t)
	s := e.signer(t)
	run(t, s)
	signed := reserveOK(t, s, "aaaaaaaaaaaaaaaa")
	_, ok := s.ReportClean(context.Background(), report(signed.GetPaymentId(), "bbbbbbbbbbbbbbbb"))
	eq(t, ok, false)
	waitFor(t, "the refusal line", func() bool {
		return len(e.logs.records(t, msgReportRefused)) == 1
	})
	eq(t, e.fake.ReportCalls(), 1)
}

func TestSignerLogsNoPayload(t *testing.T) {
	e := newSignerEnv(t)
	e.s.ReportQueue = 1
	s := e.signer(t)
	run(t, s)
	signed := reserveOK(t, s, "aaaaaaaaaaaaaaaa")
	s.Report(report(signed.GetPaymentId(), signed.GetPaymentRef()))
	waitFor(t, "the report", func() bool { return len(e.fake.Reports()) == 1 })
	idle(t, s)
	s.Report(report(signed.GetPaymentId(), "bbbbbbbbbbbbbbbb"))
	waitFor(t, "the refusal", func() bool { return len(e.logs.records(t, msgReportRefused)) == 1 })
	idle(t, s)
	e.fake.OnReport(func(context.Context, int, *paymentsv1.ReportOutcomeRequest) (
		*paymentsv1.ReportOutcomeResponse, error,
	) {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("restarting"))
	})
	s.Report(report(signed.GetPaymentId(), signed.GetPaymentRef()))
	s.Report(report(signed.GetPaymentId(), signed.GetPaymentRef()))
	eq(t, len(e.logs.records(t, msgQueueFull)), 1)
	waitFor(t, "the drop", func() bool { return len(e.logs.records(t, msgReportDropped)) == 1 })
	e.fake.OnReport(nil)
	_, _ = s.ReportClean(context.Background(),
		report(signed.GetPaymentId(), signed.GetPaymentRef()))
	e.s.PaymentsTimeout = settings.Duration(50 * time.Millisecond)
	short := e.signer(t)
	e.fake.Delay(time.Second)
	_, err := short.Reserve(context.Background(), reserveRequest("cccccccccccccccc"))
	if err == nil {
		t.Fatal("want a deadline")
	}
	waitFor(t, "the reserve line", func() bool {
		return len(e.logs.records(t, msgReserveFailed)) == 1
	})

	tx, err := base64.StdEncoding.DecodeString(signed.GetPaymentSignature())
	if err != nil {
		t.Fatal(err)
	}
	logs := e.logs.String()
	for _, secret := range []string{
		signed.GetPaymentSignature(),
		string(tx),
		"fake-aaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbb",
		"cccccccccccccccc",
		signed.GetPaymentId(),
		testPayTo,
		required(1000),
		"api.example.com",
		"weather",
	} {
		if strings.Contains(logs, secret) {
			t.Fatalf("the logs hold %q:\n%s", secret, logs)
		}
	}
}

func TestSignerLogsNoPaymentsText(t *testing.T) {
	const (
		marker     = "zq-payments-own-words-41"
		ref        = "aaaaaaaaaaaaaaaa"
		paymentRef = "pref_eeeeeeeeeeee"
		paymentID  = "pay_7c1e"
		host       = "api.example.com"
	)
	text := fmt.Sprintf("%s: ref %s, payment_ref %s, payment %s, pay_to %s, host %s",
		marker, ref, paymentRef, paymentID, testPayTo, host)
	meta := map[string]string{
		"ref": ref, "payment_ref": paymentRef, "payment_id": paymentID, "pay_to": testPayTo,
		"note": marker,
	}
	onReport := func(code connect.Code, reason string) x402test.ReportFunc {
		return func(context.Context, int, *paymentsv1.ReportOutcomeRequest) (
			*paymentsv1.ReportOutcomeResponse, error,
		) {
			return nil, paymentsError(code, text, reason, meta)
		}
	}
	for _, tc := range []struct {
		name, msg, code, reason string
		act                     func(*testing.T, *signerEnv, *Signer)
	}{
		{
			name: "a refused report", msg: msgReportRefused, code: "failed_precondition",
			reason: "REF_CONFLICT",
			act: func(_ *testing.T, e *signerEnv, s *Signer) {
				e.fake.OnReport(onReport(connect.CodeFailedPrecondition, "REF_CONFLICT"))
				s.Report(report(paymentID, ref))
			},
		},
		{
			name: "a refused clean report", msg: msgReportRefused, code: "failed_precondition",
			reason: "REF_CONFLICT",
			act: func(t *testing.T, e *signerEnv, s *Signer) {
				e.fake.OnReport(onReport(connect.CodeFailedPrecondition, "REF_CONFLICT"))
				if _, ok := s.ReportClean(context.Background(), report(paymentID, ref)); ok {
					t.Fatal("want a refusal")
				}
			},
		},
		{
			name: "a dropped report", msg: msgReportDropped, code: "unavailable",
			reason: "PAYMENTS_DRAINING",
			act: func(_ *testing.T, e *signerEnv, s *Signer) {
				e.fake.OnReport(onReport(connect.CodeUnavailable, "PAYMENTS_DRAINING"))
				s.Report(report(paymentID, ref))
			},
		},
		{
			name: "a failed reserve", msg: msgReserveFailed, code: "internal",
			reason: "SIGNER_FAULT",
			act: func(t *testing.T, e *signerEnv, s *Signer) {
				e.fake.OnReserve(func(context.Context, *paymentsv1.ReserveAndSignRequest) (
					*paymentsv1.ReserveAndSignResponse, error,
				) {
					return nil, paymentsError(connect.CodeInternal, text, "SIGNER_FAULT", meta)
				})
				if _, err := s.Reserve(context.Background(), reserveRequest(ref)); err == nil {
					t.Fatal("want an error")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSignerEnv(t)
			s := e.signer(t)
			run(t, s)
			tc.act(t, e, s)
			waitFor(t, "the line", func() bool { return len(e.logs.records(t, tc.msg)) == 1 })
			rec := e.logs.records(t, tc.msg)[0]
			eq(t, rec["code"], any(tc.code))
			eq(t, rec["reason"], any(tc.reason))
			if _, has := rec["err"]; has {
				t.Fatalf("the line quotes Payments' error: %v", rec)
			}
			logs := e.logs.String()
			for _, kept := range []string{marker, ref, paymentRef, paymentID, testPayTo, host} {
				if strings.Contains(logs, kept) {
					t.Fatalf("the logs hold %q:\n%s", kept, logs)
				}
			}
		})
	}
}

// anyReport is a report for a payment the fake never signed
func anyReport(*testing.T, *Signer) *paymentsv1.ReportOutcomeRequest {
	return report("pay_9", "aaaaaaaaaaaaaaaa")
}

// refuseWith answers every report FailedPrecondition with an ErrorInfo of reason
func refuseWith(reason string) x402test.ReportFunc {
	return func(context.Context, int, *paymentsv1.ReportOutcomeRequest) (
		*paymentsv1.ReportOutcomeResponse, error,
	) {
		return nil, paymentsError(connect.CodeFailedPrecondition, "refused", reason, nil)
	}
}

// paymentsError is an error as Payments sends one, with an ErrorInfo of reason and meta
func paymentsError(code connect.Code, text, reason string, meta map[string]string) error {
	err := connect.NewError(code, errors.New(text))
	d, derr := connect.NewErrorDetail(&errdetails.ErrorInfo{
		Reason: reason, Domain: "bugnet.payments", Metadata: meta,
	})
	if derr != nil {
		panic(derr)
	}
	err.AddDetail(d)
	return err
}
