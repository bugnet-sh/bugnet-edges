package transfer

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	upload   = routerv1.TransferDirection_TRANSFER_DIRECTION_UPLOAD
	download = routerv1.TransferDirection_TRANSFER_DIRECTION_DOWNLOAD
	gib      = 1 << 30
)

// file is one transfer URL the fake router knows
type file struct {
	id   string
	dir  routerv1.TransferDirection
	size uint64
	data []byte // a download's bytes
	name string
	etag string
	sha  []byte // an upload's expected digest, a download's digest from mint

	used    bool
	claims  int
	written []byte // an upload's committed bytes

	// unverified ends a download's stream after its bytes without the verified message
	unverified bool
	// failAfter fails a download's stream with FILE_CHANGED after that many messages, 0 never
	failAfter int
	// holdLast keeps a download's stream open before its last message until the edge ends it
	holdLast bool
	// stall makes an upload's stream stop reading after its first bytes until closed
	stall chan struct{}
	got   int64 // bytes an upload's stream read
	// hardStop puts the URL's max_duration that far from its open, 30 minutes when 0
	hardStop time.Duration
	// streamErr, when set, answers the file's ReadTransfer and WriteTransfer streams
	streamErr error
	writes    int // upload streams that named this file and ended
}

// fakeRouter is an EdgeService that serves transfers from memory and records every call
type fakeRouter struct {
	routerv1connect.UnimplementedEdgeServiceHandler

	mu       sync.Mutex
	files    map[string]*file // by token
	opens    []*routerv1.OpenTransferRequest
	reads    []*routerv1.ReadTransferRequest
	received int64 // bytes WriteTransfer read
	aborted  int   // WriteTransfer streams that ended without a clean close
	readSent int64 // bytes ReadTransfer sent
	readsCut int   // ReadTransfer streams the edge ended before their last message
	usage    map[string][2]uint64
	// openErr, when set, answers every OpenTransfer
	openErr error
	// deadline is the placement's deadline, an hour from each call when zero
	deadline time.Time
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{files: map[string]*file{}, usage: map[string][2]uint64{}}
}

// serve runs the fake over h2c and HTTP/1.1 until the test ends
func (f *fakeRouter) serve(t interface {
	Cleanup(func())
}) string {
	mux := http.NewServeMux()
	mux.Handle(routerv1connect.NewEdgeServiceHandler(f))
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "bnx_" + base64.RawURLEncoding.EncodeToString(b)
}

func transferID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// add registers a transfer and answers its token
func (f *fakeRouter) add(x *file) string {
	tok := newToken()
	x.id = transferID(tok)
	if x.dir == download {
		x.size = uint64(len(x.data))
		if x.etag == "" {
			x.etag = fmt.Sprintf(`"%x-1"`, x.size)
		}
		if x.name == "" {
			x.name = "out.bin"
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[tok] = x
	return tok
}

func (f *fakeRouter) byID(id string) *file {
	for _, x := range f.files {
		if x.id == id {
			return x
		}
	}
	return nil
}

// slowDown is the router's RATE_LIMITED refusal with a RetryInfo of delay
func slowDown(delay time.Duration) error {
	ce := refusal(connect.CodeResourceExhausted, "RATE_LIMITED")
	d, _ := connect.NewErrorDetail(&errdetails.RetryInfo{RetryDelay: durationpb.New(delay)})
	ce.AddDetail(d)
	return ce
}

func refusal(code connect.Code, reason string) *connect.Error {
	ce := connect.NewError(code, errors.New(reason))
	d, _ := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: reason, Domain: "bugnet.router"})
	ce.AddDetail(d)
	return ce
}

func (f *fakeRouter) OpenTransfer(
	_ context.Context, req *connect.Request[routerv1.OpenTransferRequest],
) (*connect.Response[routerv1.OpenTransferResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens = append(f.opens, req.Msg)
	if f.openErr != nil {
		return nil, f.openErr
	}
	x, ok := f.files[req.Msg.GetToken()]
	switch {
	case !ok:
		return nil, refusal(connect.CodeNotFound, "TOKEN_UNKNOWN")
	case x.dir != req.Msg.GetDirection():
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("wrong way"))
	case x.used:
		return nil, refusal(connect.CodeFailedPrecondition, "TOKEN_USED")
	}
	if !req.Msg.GetProbe() {
		x.claims++
	}
	now := time.Now()
	expires := f.deadlineLocked()
	stop := now.Add(cmp.Or(x.hardStop, 30*time.Minute))
	out := &routerv1.OpenTransferResponse{
		TransferId: x.id, Lease: "lease-" + x.id[:4], PlacementId: "p1", FileName: x.name,
		Size: x.size, Etag: x.etag, HardStop: timestamppb.New(minTime(expires, stop)),
		ExpiresAt: timestamppb.New(expires),
		Budget:    &routerv1.EdgeBudget{BytesRemaining: gib},
	}
	if x.dir == download {
		out.ModifiedAt, out.Sha256 = timestamppb.New(now.Add(-time.Hour)), x.sha
	}
	return connect.NewResponse(out), nil
}

func (f *fakeRouter) ReadTransfer(
	ctx context.Context, req *connect.Request[routerv1.ReadTransferRequest],
	out *connect.ServerStream[routerv1.ReadTransferResponse],
) error {
	f.mu.Lock()
	f.reads = append(f.reads, req.Msg)
	x := f.byID(req.Msg.GetTransferId())
	f.mu.Unlock()
	if x == nil {
		return refusal(connect.CodeNotFound, "TOKEN_UNKNOWN")
	}
	if x.streamErr != nil {
		return x.streamErr
	}
	off, n := req.Msg.GetOffset(), req.Msg.GetLength()
	if off > x.size || n > x.size-off {
		return refusal(connect.CodeOutOfRange, "RANGE")
	}
	if n == 0 {
		n = x.size - off
	}
	data := x.data[off : off+n]
	sent := 0
	for {
		piece := data[:min(len(data), 256<<10)]
		data = data[len(piece):]
		last := len(data) == 0
		if x.failAfter > 0 && sent == x.failAfter {
			return refusal(connect.CodeFailedPrecondition, "FILE_CHANGED")
		}
		if last && x.holdLast {
			<-ctx.Done()
			f.cut()
			return ctx.Err()
		}
		msg := &routerv1.ReadTransferResponse{Data: piece, Verified: last && !x.unverified}
		if err := out.Send(msg); err != nil {
			f.cut()
			return err
		}
		f.mu.Lock()
		f.readSent += int64(len(piece))
		f.mu.Unlock()
		sent++
		if last {
			break
		}
		if err := ctx.Err(); err != nil {
			f.cut()
			return err
		}
	}
	if !x.unverified && off+n == x.size {
		f.mu.Lock()
		x.used = true
		f.mu.Unlock()
	}
	return nil
}

func (f *fakeRouter) WriteTransfer(
	ctx context.Context, in *connect.ClientStream[routerv1.WriteTransferRequest],
) (*connect.Response[routerv1.WriteTransferResponse], error) {
	if !in.Receive() {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("no first part"))
	}
	first := in.Msg()
	f.mu.Lock()
	x := f.byID(first.GetTransferId())
	f.mu.Unlock()
	if x == nil || first.GetLease() != "lease-"+x.id[:4] {
		return nil, refusal(connect.CodeNotFound, "TOKEN_UNKNOWN")
	}
	defer func() {
		f.mu.Lock()
		x.writes++
		f.mu.Unlock()
	}()
	if x.streamErr != nil {
		return nil, x.streamErr
	}
	var got bytes.Buffer
	stalled := false
	take := func(b []byte) {
		got.Write(b)
		f.mu.Lock()
		f.received += int64(len(b))
		x.got += int64(len(b))
		f.mu.Unlock()
		if x.stall != nil && got.Len() > 0 && !stalled {
			stalled = true
			select {
			case <-x.stall:
			case <-ctx.Done():
			}
		}
	}
	take(first.GetData())
	for in.Receive() {
		take(in.Msg().GetData())
	}
	if err := in.Err(); err != nil {
		f.mu.Lock()
		f.aborted++
		f.mu.Unlock()
		return nil, err
	}
	if uint64(got.Len()) != x.size {
		return nil, refusal(connect.CodeInvalidArgument, "SIZE_MISMATCH")
	}
	sum := sha256.Sum256(got.Bytes())
	if x.sha != nil && !bytes.Equal(sum[:], x.sha) {
		return nil, refusal(connect.CodeDataLoss, "CHECKSUM_MISMATCH")
	}
	f.mu.Lock()
	x.used, x.written = true, got.Bytes()
	f.mu.Unlock()
	return connect.NewResponse(&routerv1.WriteTransferResponse{
		Path: "/root/" + x.name, Size: x.size, Sha256: sum[:],
	}), nil
}

func (f *fakeRouter) ReportEdgeUsage(
	_ context.Context, req *connect.Request[routerv1.ReportEdgeUsageRequest],
) (*connect.Response[routerv1.ReportEdgeUsageResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	left := map[string]uint64{}
	for _, u := range req.Msg.GetUsage() {
		was := f.usage[u.GetPlacementId()]
		f.usage[u.GetPlacementId()] = [2]uint64{was[0] + u.GetBytesIn(), was[1] + u.GetBytesOut()}
		left[u.GetPlacementId()] = gib
	}
	return connect.NewResponse(&routerv1.ReportEdgeUsageResponse{BytesRemaining: left}), nil
}

func (f *fakeRouter) CheckEdgeLeases(
	_ context.Context, req *connect.Request[routerv1.CheckEdgeLeasesRequest],
) (*connect.Response[routerv1.CheckEdgeLeasesResponse], error) {
	f.mu.Lock()
	deadline := f.deadlineLocked()
	f.mu.Unlock()
	out := &routerv1.CheckEdgeLeasesResponse{Leases: map[string]*routerv1.EdgeLease{}}
	for _, id := range req.Msg.GetPlacementIds() {
		out.Leases[id] = &routerv1.EdgeLease{
			Deadline: timestamppb.New(deadline), BytesRemaining: gib,
		}
	}
	return connect.NewResponse(out), nil
}

func (f *fakeRouter) WatchEdgeEvents(
	ctx context.Context, _ *connect.Request[routerv1.WatchEdgeEventsRequest],
	_ *connect.ServerStream[routerv1.WatchEdgeEventsResponse],
) error {
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeRouter) deadlineLocked() time.Time {
	if f.deadline.IsZero() {
		return time.Now().Add(time.Hour)
	}
	return f.deadline
}

// setDeadline puts the placement's deadline at t
func (f *fakeRouter) setDeadline(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadline = t
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func (f *fakeRouter) openCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.opens)
}

func (f *fakeRouter) lastOpen() *routerv1.OpenTransferRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens[len(f.opens)-1]
}

func (f *fakeRouter) bytesReceived() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.received
}

func (f *fakeRouter) used(tok string) (bool, []byte, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	x := f.files[tok]
	return x.used, x.written, x.claims
}

// gotBytes is what each upload's stream read, in the order of toks
func (f *fakeRouter) gotBytes(toks ...string) []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []int64
	for _, tok := range toks {
		out = append(out, f.files[tok].got)
	}
	return out
}

func (f *fakeRouter) cut() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readsCut++
}

// reading is the bytes every ReadTransfer sent and the streams the edge cut
func (f *fakeRouter) reading() (int64, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.readSent, f.readsCut
}

// writesOf is the upload streams that named tok's file and ended
func (f *fakeRouter) writesOf(tok string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.files[tok].writes
}

func (f *fakeRouter) abortedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.aborted
}

func (f *fakeRouter) usageOf(placement string) [2]uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.usage[placement]
}

// discard reads a body to its end and closes it
func discard(r io.ReadCloser) {
	_, _ = io.Copy(io.Discard, r)
	_ = r.Close()
}
