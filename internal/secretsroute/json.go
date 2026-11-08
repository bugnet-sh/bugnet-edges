package secretsroute

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var errBody = errors.New("the body is not the JSON of this call")

// specJSON is a SecretSpec in the proto's JSON names
type specJSON struct {
	Name        string   `json:"name"`
	Hosts       []string `json:"hosts"`
	HeaderNames []string `json:"headerNames"`
	FetchOnly   bool     `json:"fetchOnly"`
}

type valueJSON struct {
	KeyID string `json:"keyId"`
	Box   string `json:"box"`
}

type sealingKeyJSON struct {
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Binding   string `json:"binding"`
}

type secretJSON struct {
	Spec          specJSON `json:"spec"`
	State         string   `json:"state"`
	UpdatedAt     string   `json:"updatedAt"`
	FailureReason string   `json:"failureReason"`
}

type linkJSON struct {
	PairingCode      string           `json:"pairingCode"`
	SourceLabel      string           `json:"sourceLabel"`
	SandboxCreatedAt string           `json:"sandboxCreatedAt"`
	ExpiresAt        string           `json:"expiresAt"`
	Suggested        specJSON         `json:"suggested"`
	SealingKeys      []sealingKeyJSON `json:"sealingKeys"`
}

type keysJSON struct {
	SealingKeys []sealingKeyJSON `json:"sealingKeys"`
}

type submitJSON struct {
	Secret secretJSON `json:"secret"`
}

type putJSON struct {
	Secret   secretJSON `json:"secret"`
	Replaced bool       `json:"replaced"`
}

// submitBody is PUT /v1/links/<token>/secret
type submitBody struct {
	Spec         specJSON  `json:"spec"`
	Value        valueJSON `json:"value"`
	SubmissionID string    `json:"submissionId"`
	// ClientIP is read only to refuse it, the route fills the address itself
	ClientIP *json.RawMessage `json:"clientIp"`
}

// putBody is PUT /v1/secrets/<name>
type putBody struct {
	Spec           specJSON         `json:"spec"`
	Value          valueJSON        `json:"value"`
	IdempotencyKey string           `json:"idempotencyKey"`
	ClientIP       *json.RawMessage `json:"clientIp"`
}

// decode reads one JSON object that holds only known fields and nothing after it
func decode(body []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return errBody
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errBody
	}
	return nil
}

func (s specJSON) proto() *routerv1.SecretSpec {
	return &routerv1.SecretSpec{
		Name: s.Name, Hosts: s.Hosts, HeaderNames: s.HeaderNames, FetchOnly: s.FetchOnly,
	}
}

// proto decodes the box, which is base64url without padding
func (v valueJSON) proto() (*routerv1.SealedValue, error) {
	box, err := base64.RawURLEncoding.DecodeString(v.Box)
	if err != nil {
		return nil, errBody
	}
	return &routerv1.SealedValue{KeyId: v.KeyID, Box: box}, nil
}

func specOf(s *routerv1.SecretSpec) specJSON {
	return specJSON{
		Name: s.GetName(), Hosts: nonNil(s.GetHosts()), HeaderNames: nonNil(s.GetHeaderNames()),
		FetchOnly: s.GetFetchOnly(),
	}
}

// nonNil keeps an empty list as [] rather than null
func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func keysOf(keys []*routerv1.SealingKey) []sealingKeyJSON {
	out := make([]sealingKeyJSON, 0, len(keys))
	for _, k := range keys {
		out = append(out, sealingKeyJSON{
			KeyID:     k.GetKeyId(),
			PublicKey: base64.RawURLEncoding.EncodeToString(k.GetPublicKey()),
			Binding:   k.GetBinding(),
		})
	}
	return out
}

// stamp is an RFC 3339 time in UTC, empty when the router sent none
func stamp(t *timestamppb.Timestamp) string {
	if t == nil {
		return ""
	}
	return t.AsTime().UTC().Format(time.RFC3339)
}

// stateName is the short name of a secret state, empty for one the route does not know
func stateName(s routerv1.SecretState) string {
	switch s {
	case routerv1.SecretState_SECRET_STATE_APPLYING:
		return "APPLYING"
	case routerv1.SecretState_SECRET_STATE_ACTIVE:
		return "ACTIVE"
	case routerv1.SecretState_SECRET_STATE_FAILED:
		return "FAILED"
	}
	return ""
}

func secretOf(s *routerv1.SecretInfo) secretJSON {
	return secretJSON{
		Spec: specOf(s.GetSpec()), State: stateName(s.GetState()),
		UpdatedAt: stamp(s.GetUpdatedAt()), FailureReason: s.GetFailureReason(),
	}
}

func linkOf(m *routerv1.GetSecretLinkResponse) linkJSON {
	return linkJSON{
		PairingCode: m.GetPairingCode(), SourceLabel: m.GetSourceLabel(),
		SandboxCreatedAt: stamp(m.GetSandboxCreatedAt()), ExpiresAt: stamp(m.GetExpiresAt()),
		Suggested: specOf(m.GetSuggested()), SealingKeys: keysOf(m.GetSealingKeys()),
	}
}
