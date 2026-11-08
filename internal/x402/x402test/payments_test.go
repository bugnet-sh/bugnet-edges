package x402test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	paymentsv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/payments/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/payments/v1/paymentsv1connect"
)

// eq fails the test when got and want differ
func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// client calls p over mutual TLS with cert, nil for no client certificate
func client(p *Payments, ca *CA, cert *tls.Certificate) paymentsv1connect.X402SignerServiceClient {
	cfg := &tls.Config{RootCAs: ca.Pool(), ServerName: ServerName, MinVersion: tls.VersionTLS13}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}}
	return paymentsv1connect.NewX402SignerServiceClient(hc, p.URL)
}

// payTo is a base58 address of 32 bytes
const payTo = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"

// solanaEntry is an exact USDC entry with spacing and key order a seller may use
const solanaEntry = `{ "payTo": "` + payTo + `", "scheme":"exact", "network": "` +
	solanaMainnet + `", "asset": "` + usdcMint + `", "amount": "2500",
	"maxTimeoutSeconds": 60, "extra": {"feePayer": "` + payTo + `"} }`

// header is a v2 PAYMENT-REQUIRED value whose second entry is solanaEntry
func header() string {
	raw := `{"x402Version":2,"resource":{"url":"https://api.example.com/x"},"accepts":[` +
		`{"scheme":"exact","network":"eip155:8453","asset":"0x1","amount":"1","payTo":"0x2"},` +
		solanaEntry + `]}`
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func request(ref string) *paymentsv1.ReserveAndSignRequest {
	sum := sha256.Sum256([]byte(ref))
	return &paymentsv1.ReserveAndSignRequest{
		PlacementId: "pl_a", Ref: ref, Method: "GET", Host: "api.example.com", Path: "/x",
		BodySha256: sum[:], TargetSha256: sum[:], PaymentRequired: header(),
	}
}

func reserve(
	t *testing.T, c paymentsv1connect.X402SignerServiceClient, r *paymentsv1.ReserveAndSignRequest,
) *paymentsv1.ReserveAndSignResponse {
	t.Helper()
	res, err := c.ReserveAndSign(context.Background(), connect.NewRequest(r))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg
}

func TestFakePaymentFormat(t *testing.T) {
	ca := NewCA(t)
	p := StartPayments(t, ca)
	pair := ca.Client(t)
	signed := reserve(t, client(p, ca, &pair), request("aaaaaaaaaaaaaaaa")).GetSigned()
	raw, err := base64.StdEncoding.DecodeString(signed.GetPaymentSignature())
	if err != nil {
		t.Fatal(err)
	}
	eq(t, string(raw), `{"x402Version":2,"accepted":`+solanaEntry+
		`,"payload":{"transaction":"fake-aaaaaaaaaaaaaaaa"}}`)
	var top struct {
		Version  int             `json:"x402Version"`
		Accepted json.RawMessage `json:"accepted"`
		Payload  struct {
			Transaction string `json:"transaction"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	eq(t, top.Version, 2)
	eq(t, string(top.Accepted), solanaEntry)
	eq(t, top.Payload.Transaction, "fake-aaaaaaaaaaaaaaaa")
	eq(t, signed.GetAmountMicros(), int64(2500))
	eq(t, signed.GetPayTo(), payTo)
	eq(t, signed.GetPaymentRef(), "aaaaaaaaaaaaaaaa")
	eq(t, signed.GetAllowanceLeftMicros(), int64(StartLeft-2500))
	eq(t, signed.GetResend(), false)
	eq(t, p.Signings(), 1)
}

func TestFakeRefusesOtherClients(t *testing.T) {
	ca := NewCA(t)
	p := StartPayments(t, ca)
	foreign := NewCA(t).Client(t)
	key := NewKey(t)
	server := Pair(t, ca.Issue(t, &key.PublicKey, ClientName, x509.ExtKeyUsageServerAuth,
		time.Now().AddDate(1, 0, 0)), key)
	other := Pair(t, ca.Issue(t, &key.PublicKey, "other.internal", x509.ExtKeyUsageClientAuth,
		time.Now().AddDate(1, 0, 0)), key)
	for name, cert := range map[string]*tls.Certificate{
		"none":                nil,
		"another CA":          &foreign,
		"another name":        &other,
		"a server-only usage": &server,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := client(p, ca, cert).ReserveAndSign(context.Background(),
				connect.NewRequest(request("aaaaaaaaaaaaaaaa")))
			if err == nil {
				t.Fatal("want a refused handshake")
			}
		})
	}
	eq(t, len(p.Calls()), 0)
}

func TestFakeResendsAnUncleanRow(t *testing.T) {
	ca := NewCA(t)
	p := StartPayments(t, ca)
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	p.SetClock(func() time.Time { return now })
	pair := ca.Client(t)
	c := client(p, ca, &pair)
	first := reserve(t, c, request("aaaaaaaaaaaaaaaa")).GetSigned()
	eq(t, first.GetKeepUntil().AsTime(), now.Add(KeepFor))

	again := request("aaaaaaaaaaaaaaaa")
	again.Ref = "bbbbbbbbbbbbbbbb"
	resend := reserve(t, c, again).GetSigned()
	eq(t, resend.GetResend(), true)
	eq(t, resend.GetPaymentRef(), "aaaaaaaaaaaaaaaa")
	eq(t, resend.GetPaymentSignature(), first.GetPaymentSignature())
	eq(t, resend.GetPaymentId(), first.GetPaymentId())
	eq(t, p.Signings(), 1)

	_, err := c.ReportOutcome(context.Background(), connect.NewRequest(
		&paymentsv1.ReportOutcomeRequest{PaymentId: first.GetPaymentId(), Ref: "bbbbbbbbbbbbbbbb"}))
	eq(t, connect.CodeOf(err), connect.CodeFailedPrecondition)
	_, err = c.ReportOutcome(context.Background(), connect.NewRequest(
		&paymentsv1.ReportOutcomeRequest{
			PaymentId: first.GetPaymentId(), Ref: first.GetPaymentRef(), HttpStatus: 200,
			Hint: paymentsv1.SellerHint_SELLER_HINT_SUCCESS,
		}))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, p.ReportCalls(), 2)
	eq(t, len(p.Reports()), 1)
	fresh := reserve(t, c, again).GetSigned()
	eq(t, fresh.GetResend(), false)
	eq(t, fresh.GetPaymentRef(), "bbbbbbbbbbbbbbbb")
	eq(t, p.Signings(), 2)

	now = now.Add(BlockhashLife)
	third := request("aaaaaaaaaaaaaaaa")
	third.Ref = "cccccccccccccccc"
	eq(t, reserve(t, c, third).GetSigned().GetResend(), false)
}

func TestFakeRefusesWhatItCannotSign(t *testing.T) {
	ca := NewCA(t)
	p := StartPayments(t, ca)
	pair := ca.Client(t)
	c := client(p, ca, &pair)
	for top, reason := range map[string]string{
		"":                               "not_x402",
		`{"x402Version":1,"accepts":[]}`: "version_unsupported",
		`{"x402Version":2,"accepts":[]}`: "network_unsupported",
	} {
		r := request("aaaaaaaaaaaaaaaa")
		r.PaymentRequired = "%%%"
		if top != "" {
			r.PaymentRequired = base64.StdEncoding.EncodeToString([]byte(top))
		}
		eq(t, reserve(t, c, r).GetRefused().GetReason(), reason)
	}
	eq(t, p.Signings(), 0)
}

func TestWriteDevLayout(t *testing.T) {
	ca := NewCA(t)
	dir := t.TempDir()
	ca.WriteDev(t, dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string]os.FileMode{}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		modes[e.Name()] = info.Mode().Perm()
	}
	eq(t, modes, map[string]os.FileMode{
		"internal-ca.pem":        0o644,
		"egress-x402-client.pem": 0o644,
		"egress_x402_client_key": 0o600,
		"x402-server.pem":        0o644,
		"payments.env.add":       0o600,
	})

	env, err := os.ReadFile(filepath.Join(dir, "payments.env.add"))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, bytes.Count(env, []byte("\n")), 1)
	value, found := strings.CutPrefix(strings.TrimSuffix(string(env), "\n"), "BUGNET_X402_TLS_KEY=")
	eq(t, found, true)
	keyPEM, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	eq(t, block.Type, "PRIVATE KEY")

	back := ReadDev(t, dir)
	eq(t, back.Cert.Raw, ca.Cert.Raw)
	eq(t, back.Server.Certificate, ca.Server.Certificate)
	eq(t, back.ClientKey.Equal(ca.ClientKey), true)
	eq(t, back.ClientPEM, ca.ClientPEM)
	leaf, err := x509.ParseCertificate(back.Server.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	eq(t, leaf.DNSNames, []string{ServerName})
	eq(t, slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}), true)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: ServerName})
	if err != nil {
		t.Fatal(err)
	}
}
