package sessionsroute

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
)

const (
	// capRetry is the Retry-After for a live call past a stream cap
	capRetry = 5 * time.Second
	// reasonClosed ends a deleted record's streams, as the router's own end would
	reasonClosed = "closed"
)

// The live frames of SP 7.3.1, the record's frame shape for out
type (
	outFrame struct {
		S  string `json:"s"`
		T  string `json:"t"`
		CR bool   `json:"cr"`
	}
	skipFrame struct {
		OutBytes uint64 `json:"outBytes"`
		ErrBytes uint64 `json:"errBytes"`
	}
	exitFrame struct {
		ExitCode int32  `json:"exitCode"`
		OOM      bool   `json:"oom"`
		PeakMiB  uint32 `json:"peakMib"`
	}
	endFrame struct {
		Reason string `json:"reason"`
	}
)

// watch is POST /v1/s/<id>/jobs/<seq>/live, WatchSessionJob as server-sent events
func (h *Handler) watch(q *call, body []byte, seq uint32) {
	b, ok := h.admit(q, body)
	if !ok {
		return
	}
	s, refusal := h.live.add(q.id, q.ip)
	switch refusal {
	case http.StatusTooManyRequests:
		h.answer(q, refusal, capRetry)
		return
	case http.StatusServiceUnavailable:
		h.answer(q, refusal, busyRetry)
		return
	}
	defer h.live.remove(s)

	ctx, cancel := context.WithCancel(q.r.Context())
	defer cancel()
	// The call itself waits for the router's first answer, so it runs beside the first frame's
	// wait. callErr is read only once ended is closed
	frames := make(chan *routerv1.WatchSessionJobResponse)
	ended := make(chan struct{})
	var callErr error
	go func() {
		defer close(ended)
		stream, err := h.newCall().WatchSessionJob(ctx, connect.NewRequest(
			&routerv1.WatchSessionJobRequest{Id: q.id, Key: b.K, Seq: seq, Cursor: b.Cursor}))
		if err != nil {
			callErr = err
			return
		}
		defer func() { _ = stream.Close() }()
		for stream.Receive() {
			select {
			case frames <- stream.Msg():
			case <-ctx.Done():
				return
			}
		}
		callErr = stream.Err()
	}()
	defer func() {
		cancel()
		<-ended
	}()

	// A refusal comes before any frame, so the first one decides between an error and the 200
	var first *routerv1.WatchSessionJobResponse
	wait := time.NewTimer(h.o.FirstFrame)
	defer wait.Stop()
	select {
	case first = <-frames:
		h.good.add(q.sum)
	case <-ended:
		if callErr != nil {
			h.refused(q, callErr, false)
		} else {
			h.answer(q, http.StatusServiceUnavailable, busyRetry)
		}
		return
	case <-wait.C:
	case reason := <-s.stop:
		if reason == reasonClosed {
			h.answer(q, http.StatusNotFound, 0)
		} else {
			h.answer(q, http.StatusServiceUnavailable, busyRetry)
		}
		return
	case <-ctx.Done():
		q.status = 499
		return
	}

	hd := q.w.Header()
	h.o.Bundle.setHeaders(hd)
	hd.Set("Content-Type", "text/event-stream")
	// An HTTP/1.1 stream keeps its connection, so no write deadline outlives it
	if q.r.ProtoMajor == 1 {
		hd.Set("Connection", "close")
	}
	q.status = http.StatusOK
	q.w.WriteHeader(http.StatusOK)
	out := &sseWriter{w: q.w, rc: http.NewResponseController(q.w), timeout: h.o.WriteTimeout}
	defer out.last()
	if out.flush() != nil {
		return
	}
	if first != nil {
		if end, err := out.frame(first); end || err != nil {
			return
		}
	}
	keep := time.NewTicker(h.o.Keepalive)
	defer keep.Stop()
	for {
		select {
		case m := <-frames:
			if end, err := out.frame(m); end || err != nil {
				return
			}
		case <-ended:
			return
		case <-keep.C:
			if out.write([]byte(": keepalive\n\n")) != nil {
				return
			}
		case reason := <-s.stop:
			if reason != "" {
				data, _ := json.Marshal(endFrame{Reason: reason})
				_ = out.event("end", "", data)
			}
			return
		case <-ctx.Done():
			return
		}
	}
}

// sseWriter writes events, each write under its own deadline so a stalled reader frees its slot
type sseWriter struct {
	w       http.ResponseWriter
	rc      *http.ResponseController
	timeout time.Duration
}

// frame writes one router frame as its event, end true after the stream's end frame
func (s *sseWriter) frame(m *routerv1.WatchSessionJobResponse) (end bool, err error) {
	var name string
	var data any
	switch f := m.GetFrame().(type) {
	case *routerv1.WatchSessionJobResponse_Text:
		side := "o"
		if f.Text.GetStream() == routerv1.OutputStream_OUTPUT_STREAM_STDERR {
			side = "e"
		}
		name, data = "out", outFrame{S: side, T: f.Text.GetText(), CR: f.Text.GetOverwrite()}
	case *routerv1.WatchSessionJobResponse_Skip:
		name, data = "skip", skipFrame{
			OutBytes: f.Skip.GetStdoutOffset(), ErrBytes: f.Skip.GetStderrOffset()}
	case *routerv1.WatchSessionJobResponse_Exit:
		name, data = "exit", exitFrame{ExitCode: f.Exit.GetExitCode(),
			OOM: f.Exit.GetOomKilled(), PeakMiB: f.Exit.GetPeakMemoryMib()}
	case *routerv1.WatchSessionJobResponse_End:
		name, data, end = "end", endFrame{Reason: f.End.GetReason()}, true
	default:
		// Heartbeats, and frames a newer router adds, the edge's own keepalive standing in
		return false, nil
	}
	b, err := json.Marshal(data)
	if err != nil {
		return true, err
	}
	return end, s.event(name, m.GetCursor(), b)
}

// event writes one event, with an id line only when the router gave a cursor
func (s *sseWriter) event(name, cursor string, data []byte) error {
	var b strings.Builder
	b.WriteString("event: " + name + "\n")
	if cursor != "" && !strings.ContainsAny(cursor, "\r\n\x00") {
		b.WriteString("id: " + cursor + "\n")
	}
	b.WriteString("data: ")
	b.Write(data)
	b.WriteString("\n\n")
	return s.write([]byte(b.String()))
}

func (s *sseWriter) write(p []byte) error {
	_ = s.rc.SetWriteDeadline(time.Now().Add(s.timeout))
	if _, err := s.w.Write(p); err != nil {
		return err
	}
	return s.rc.Flush()
}

func (s *sseWriter) flush() error {
	_ = s.rc.SetWriteDeadline(time.Now().Add(s.timeout))
	return s.rc.Flush()
}

// last gives the response's end the same deadline as any write
func (s *sseWriter) last() {
	_ = s.rc.SetWriteDeadline(time.Now().Add(s.timeout))
}

/* Stream caps */

// streams holds the open live streams by record, client address and process, SP 7.4
type streams struct {
	perRecord, perIP, all int

	mu     sync.Mutex
	byID   map[string]map[*liveStream]struct{}
	byIP   map[netip.Addr]int
	total  int
	closed bool
}

// liveStream is one open stream, told on stop to end with a reason, or with none on shutdown
type liveStream struct {
	id   string
	ip   netip.Addr
	stop chan string
}

// newStreams caps streams per record, per address and in all, 0 or less being no cap
func newStreams(perRecord, perIP, all int) *streams {
	return &streams{perRecord: perRecord, perIP: perIP, all: all,
		byID: map[string]map[*liveStream]struct{}{}, byIP: map[netip.Addr]int{}}
}

// add opens a stream, or answers 429 past a cap and 503 once closed
func (s *streams) add(id string, ip netip.Addr) (*liveStream, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return nil, http.StatusServiceUnavailable
	case over(s.all, s.total), over(s.perRecord, len(s.byID[id])), over(s.perIP, s.byIP[ip]):
		return nil, http.StatusTooManyRequests
	}
	ls := &liveStream{id: id, ip: ip, stop: make(chan string, 1)}
	if s.byID[id] == nil {
		s.byID[id] = map[*liveStream]struct{}{}
	}
	s.byID[id][ls] = struct{}{}
	s.byIP[ip]++
	s.total++
	return ls, 0
}

func over(limit, n int) bool {
	return limit > 0 && n >= limit
}

func (s *streams) remove(ls *liveStream) {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.byID[ls.id]
	if _, ok := set[ls]; !ok {
		return
	}
	delete(set, ls)
	if len(set) == 0 {
		delete(s.byID, ls.id)
	}
	if s.byIP[ls.ip]--; s.byIP[ls.ip] <= 0 {
		delete(s.byIP, ls.ip)
	}
	s.total--
}

// endRecord ends every stream of the record id with the end reason closed
func (s *streams) endRecord(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ls := range s.byID[id] {
		ls.tell(reasonClosed)
	}
}

// closeAll ends every stream with no end frame and refuses new ones
func (s *streams) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, set := range s.byID {
		for ls := range set {
			ls.tell("")
		}
	}
}

func (s *streams) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

func (ls *liveStream) tell(reason string) {
	select {
	case ls.stop <- reason:
	default:
	}
}
