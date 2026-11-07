package fakeseller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/oynozan/bugnet-edges/internal/x402"
)

// reasonShape is the errorReason text a facilitator's answer passes on to the payer
var reasonShape = regexp.MustCompile(`^[a-z0-9_]{1,128}$`)

// facilitator settles through an x402 facilitator's verify and settle
type facilitator struct {
	url    string
	client *http.Client
}

// Facilitator posts x402 v2 verify then settle bodies to a facilitator
func Facilitator(url string) Settler {
	return &facilitator{
		url:    strings.TrimSuffix(url, "/"),
		client: &http.Client{Timeout: callTimeout, CheckRedirect: noRedirect},
	}
}

// facilitatorBody is what verify and settle each take
type facilitatorBody struct {
	Version      int             `json:"x402Version"`
	Payload      json.RawMessage `json:"paymentPayload"`
	Requirements json.RawMessage `json:"paymentRequirements"`
}

// Settle verifies the payload and settles it only when it is valid, answering the transaction
func (f *facilitator) Settle(ctx context.Context, p Payment) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(p.Value)
	var parts struct {
		Accepted json.RawMessage `json:"accepted"`
	}
	if err != nil || json.Unmarshal(raw, &parts) != nil || len(parts.Accepted) == 0 {
		return "", refuse(reasonUndecodable)
	}
	body := mustJSON(facilitatorBody{Version: 2, Payload: raw, Requirements: parts.Accepted})
	var v struct {
		IsValid       *bool  `json:"isValid"`
		InvalidReason string `json:"invalidReason"`
	}
	if err := f.post(ctx, "/verify", body, &v); err != nil {
		return "", err
	}
	if v.IsValid == nil {
		return "", errors.New("fakeseller: the facilitator's verify answer has no isValid")
	}
	if !*v.IsValid {
		return "", refuse(passed(v.InvalidReason))
	}
	var s struct {
		Success     *bool  `json:"success"`
		ErrorReason string `json:"errorReason"`
		Transaction string `json:"transaction"`
	}
	if err := f.post(ctx, "/settle", body, &s); err != nil {
		return "", err
	}
	if s.Success == nil {
		return "", errors.New("fakeseller: the facilitator's settle answer has no success")
	}
	if !*s.Success {
		return "", refuse(passed(s.ErrorReason))
	}
	if sig, ok := x402.Decode58(s.Transaction); !ok || len(sig) != sigBytes {
		return "", errors.New("fakeseller: the facilitator settled with no transaction signature")
	}
	return s.Transaction, nil
}

// post sends body to path and decodes the JSON answer into out, whatever its status
func (f *facilitator) post(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("fakeseller: facilitator %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("fakeseller: facilitator %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	if err := json.NewDecoder(io.LimitReader(res.Body, maxAnswer)).Decode(out); err != nil {
		return fmt.Errorf("fakeseller: facilitator %s answered %d, not JSON", path, res.StatusCode)
	}
	return nil
}

// passed is a facilitator's reason when it has the shape of one, else empty
func passed(reason string) string {
	if reasonShape.MatchString(reason) {
		return reason
	}
	return ""
}
