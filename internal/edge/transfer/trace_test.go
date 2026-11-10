package transfer

import (
	"strings"
	"testing"

	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/telemetrytest"
)

const (
	testHandle    = "sbx_incf5d4j2g46mypgm6wajtyic5"
	testPlacement = "3f6c1d52-8b8e-4b6e-9d5b-0e1f2a3b4c5d"
	routerSpanID  = "00f067aa0ba902b7"
)

// tracedHarness is a harness whose router answers an order_traceparent in the handle's trace
func tracedHarness(t *testing.T) (*harness, *telemetrytest.Telemetry, string) {
	t.Helper()
	tel := telemetrytest.New(t, "bugnet-edge", 1)
	h := newHarnessWith(t, tel.Telemetry)
	tid, _ := telemetrytest.OrderIDs(testHandle)
	h.router.orderTP = telemetrytest.Traceparent(tid, routerSpanID)
	h.router.placement = testPlacement
	return h, tel, tid
}

// settled waits until the handler has returned from n requests of method, so its spans ended
func settled(t *testing.T, h *harness, method string, n int) {
	t.Helper()
	waitFor(t, "the handler to return", func() bool { return h.finishedOf(method) >= n })
}

func TestStrangersMakeNoSpans(t *testing.T) {
	h, tel, _ := tracedHarness(t)
	for range 100 {
		h.get(t, newToken())
		h.get(t, "not-a-token")
	}
	eq(t, len(tel.Flushed(t)), 0)
}

func TestTransferSpanInOrderTrace(t *testing.T) {
	h, tel, tid := tracedHarness(t)
	tok := h.downTok([]byte("some bytes"))
	eq(t, h.get(t, tok).StatusCode, 200)
	settled(t, h, "GET", 1)
	spans := tel.Flushed(t)
	s := telemetrytest.Only(t, spans, "edge.transfer")
	eq(t, s.TraceID, tid)
	eq(t, s.ParentID, routerSpanID)
	eq[any](t, s.Attrs["bugnet.direction"], "download")
	eq[any](t, s.Attrs["bugnet.size_bytes"], int64(10))
	eq[any](t, s.Attrs["bugnet.end_cause"], "done")
	eq[any](t, s.Attrs["http.response.status_code"], int64(200))
	eq[any](t, s.Attrs["bugnet.transfer_hash"], transferID(tok)[:8])
	eq[any](t, s.Attrs["bugnet.placement_id"], testPlacement)
	read := telemetrytest.Only(t, spans, "bugnet.router.v1.EdgeService/ReadTransfer")
	eq(t, read.ParentID, s.SpanID)
	eq[any](t, read.Attrs["rpc.response.status_code"], "OK")
	// The router saw the client span as the caller's
	h.router.mu.Lock()
	defer h.router.mu.Unlock()
	eq(t, len(h.router.readTP), 1)
	eq(t, strings.Split(h.router.readTP[0], "-")[1:3], []string{tid, read.SpanID})
	// The OpenTransfer call came before the session, so it sent no header and made no span
	eq(t, len(telemetrytest.Named(spans, "bugnet.router.v1.EdgeService/OpenTransfer")), 0)
}

func TestTransferSpanBackdatedToArrival(t *testing.T) {
	h, tel, _ := tracedHarness(t)
	h.get(t, h.downTok([]byte("x")))
	settled(t, h, "GET", 1)
	s := telemetrytest.Only(t, tel.Flushed(t), "edge.transfer")
	eq(t, !s.End.Before(s.Start), true)
}

func TestEmptyOrderTraceparentMakesNoSession(t *testing.T) {
	h, tel, _ := tracedHarness(t)
	h.router.orderTP = ""
	eq(t, h.get(t, h.downTok([]byte("x"))).StatusCode, 200)
	eq(t, len(tel.Flushed(t)), 0)
}

func TestUploadSpanEndsWithItsDirection(t *testing.T) {
	h, tel, _ := tracedHarness(t)
	tok := h.upTok(3)
	eq(t, h.do(t, "PUT", "/"+tok, "abc", contentLength(3)).StatusCode, 200)
	s := telemetrytest.Only(t, tel.Flushed(t), "edge.transfer")
	eq[any](t, s.Attrs["bugnet.direction"], "upload")
	eq[any](t, s.Attrs["bugnet.size_bytes"], int64(3))
}

func TestFailedTransferSpanEndsAsError(t *testing.T) {
	h, tel, _ := tracedHarness(t)
	tok := h.upTok(5)
	// A body of another size is refused after the router opened the transfer
	eq(t, h.do(t, "PUT", "/"+tok, "ab", contentLength(2)).StatusCode, 400)
	s := telemetrytest.Only(t, tel.Flushed(t), "edge.transfer")
	eq[any](t, s.Attrs["bugnet.end_cause"], "error")
}
