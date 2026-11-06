package lease

import (
	"context"

	"connectrpc.com/connect"
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
)

// EdgeCheck checks through CheckEdgeLeases, sending the held previews and reading the revoked
func EdgeCheck(c routerv1connect.EdgeServiceClient) Check {
	return func(ctx context.Context, in CheckIn) (CheckOut, error) {
		req := &routerv1.CheckEdgeLeasesRequest{PlacementIds: in.Placements}
		for _, h := range in.Held {
			req.Previews = append(req.Previews,
				&routerv1.HeldPreview{PreviewId: h.ID, Generation: h.Generation})
		}
		res, err := c.CheckEdgeLeases(ctx, connect.NewRequest(req))
		if err != nil {
			return CheckOut{}, err
		}
		out := CheckOut{
			States:  map[string]State{},
			Revoked: res.Msg.GetRevokedPreviewIds(),
		}
		// A lease without a deadline is left out, so it ends rather than outliving its payment
		for id, l := range res.Msg.GetLeases() {
			if l.GetDeadline() != nil {
				out.States[id] = State{
					Deadline: l.GetDeadline().AsTime(), Remaining: l.GetBytesRemaining(),
				}
			}
		}
		return out, nil
	}
}

// EgressCheck checks through CheckEgressLeases, reading each placement's secrets version
func EgressCheck(c routerv1connect.EgressServiceClient) Check {
	return func(ctx context.Context, in CheckIn) (CheckOut, error) {
		res, err := c.CheckEgressLeases(ctx, connect.NewRequest(
			&routerv1.CheckEgressLeasesRequest{PlacementIds: in.Placements}))
		if err != nil {
			return CheckOut{}, err
		}
		out := CheckOut{States: map[string]State{}}
		for id, l := range res.Msg.GetLeases() {
			if l.GetDeadline() != nil {
				out.States[id] = State{
					Deadline:       l.GetDeadline().AsTime(),
					Remaining:      l.GetBytesRemaining(),
					SecretsVersion: l.GetSecretsVersion(),
				}
			}
		}
		return out, nil
	}
}
