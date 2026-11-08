package usage

import (
	"context"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
)

// EdgeSend reports through ReportEdgeUsage under reporterID
func EdgeSend(c routerv1connect.EdgeServiceClient, reporterID string) Send {
	return func(ctx context.Context, u []*routerv1.PlacementUsage) (
		map[string]uint64, map[string]uint64, error,
	) {
		res, err := c.ReportEdgeUsage(ctx, connect.NewRequest(&routerv1.ReportEdgeUsageRequest{
			ReporterId: reporterID, Usage: u,
		}))
		if err != nil {
			return nil, nil, err
		}
		return res.Msg.GetBytesRemaining(), res.Msg.GetBytesPerSecond(), nil
	}
}

// SSHSend reports through ReportSshUsage under reporterID
func SSHSend(c routerv1connect.SshGatewayServiceClient, reporterID string) Send {
	return func(ctx context.Context, u []*routerv1.PlacementUsage) (
		map[string]uint64, map[string]uint64, error,
	) {
		res, err := c.ReportSshUsage(ctx, connect.NewRequest(&routerv1.ReportSshUsageRequest{
			ReporterId: reporterID, Usage: u,
		}))
		if err != nil {
			return nil, nil, err
		}
		return res.Msg.GetBytesRemaining(), res.Msg.GetBytesPerSecond(), nil
	}
}

// EgressSend reports through ReportEgressUsage under reporterID, whose answer carries no pace
func EgressSend(c routerv1connect.EgressServiceClient, reporterID string) Send {
	return func(ctx context.Context, u []*routerv1.PlacementUsage) (
		map[string]uint64, map[string]uint64, error,
	) {
		res, err := c.ReportEgressUsage(ctx, connect.NewRequest(&routerv1.ReportEgressUsageRequest{
			ReporterId: reporterID, Usage: u,
		}))
		if err != nil {
			return nil, nil, err
		}
		return res.Msg.GetBytesRemaining(), nil, nil
	}
}
