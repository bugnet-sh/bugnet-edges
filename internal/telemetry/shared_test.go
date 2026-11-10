package telemetry_test

import (
	"testing"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"google.golang.org/protobuf/proto"

	"github.com/bugnet-sh/bugnet-edges/internal/telemetry"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/attr"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/telemetrytest"
)

// TestSharedValuesMatchTheRouters pins what the router's tests pin, the allowlist, the
// never-traced list, the derivation label and the field numbers (DP 20.5.1)
func TestSharedValuesMatchTheRouters(t *testing.T) {
	eq(t, attr.Keys(), []string{
		"bugnet.attempt", "bugnet.bytes_in", "bugnet.bytes_out", "bugnet.can_fail_over",
		"bugnet.count", "bugnet.direction", "bugnet.egress_host", "bugnet.end_cause",
		"bugnet.estimate_id", "bugnet.event_type", "bugnet.exit_code",
		"bugnet.extend_order_hash", "bugnet.forwards", "bugnet.gate_errors",
		"bugnet.handle_hash", "bugnet.job.attempt", "bugnet.job.kind", "bugnet.job.outcome",
		"bugnet.job.queue", "bugnet.job.wait_ms", "bugnet.job_id", "bugnet.link",
		"bugnet.order_hash", "bugnet.package_id", "bugnet.placement_id", "bugnet.port",
		"bugnet.preview_id", "bugnet.provider", "bugnet.provider_code", "bugnet.reason",
		"bugnet.refused", "bugnet.repaired", "bugnet.requests", "bugnet.responses_4xx",
		"bugnet.responses_5xx", "bugnet.sandbox_hash", "bugnet.sessions", "bugnet.size",
		"bugnet.size_bytes", "bugnet.state", "bugnet.swaps", "bugnet.transfer_hash",
		"bugnet.transport", "bugnet.truncated", "bugnet.websockets", "error.type",
		"http.response.status_code", "rpc.method", "rpc.response.status_code",
		"rpc.system.name",
	})
	eq(t, telemetry.NeverTraced, []string{
		"/bugnet.router.v1.EdgeService/ReportEdgeUsage",
		"/bugnet.router.v1.EdgeService/CheckEdgeLeases",
		"/bugnet.router.v1.EdgeService/WatchEdgeEvents",
		"/bugnet.router.v1.SshGatewayService/RenewSshConnection",
		"/bugnet.router.v1.SshGatewayService/CheckSshGrants",
		"/bugnet.router.v1.SshGatewayService/ReportSshUsage",
		"/bugnet.router.v1.SshGatewayService/WatchSshEvents",
		"/bugnet.router.v1.EgressService/ReportEgressUsage",
		"/bugnet.router.v1.EgressService/CheckEgressLeases",
		"/bugnet.router.v1.EgressService/WatchEgressEvents",
		"/bugnet.router.v1.EgressService/AppendX402Events",
	})
	// The derivation label and its two vectors, DP 20.2.1
	tid, sid := telemetrytest.OrderIDs("sbx_incf5d4j2g46mypgm6wajtyic5")
	eq(t, tid, "55a4dee648a7a4d0a70cd0a8b24c672f")
	eq(t, sid, "69923b8439c47854")
	tid, sid = telemetrytest.OrderIDs("sbx_7777777777777777777777777z")
	eq(t, tid, "2730084125185d2f596d4359ab9e35eb")
	eq(t, sid, "7a5546d2e76201a9")
	// The fields the router fills with the order's parent
	for _, m := range []proto.Message{&routerv1.ResolvePreviewResponse{},
		&routerv1.OpenTransferResponse{}, &routerv1.AuthorizeSshKeyResponse{},
		&routerv1.ResolveTunnelResponse{}} {
		f := m.ProtoReflect().Descriptor().Fields().ByName("order_traceparent")
		eq(t, f != nil && f.Number() == 100, true)
	}
}
