package lease

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var at = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

type edgeClient struct {
	routerv1connect.EdgeServiceClient
	got *routerv1.CheckEdgeLeasesRequest
	err error
}

func (c *edgeClient) CheckEdgeLeases(
	_ context.Context, req *connect.Request[routerv1.CheckEdgeLeasesRequest],
) (*connect.Response[routerv1.CheckEdgeLeasesResponse], error) {
	c.got = req.Msg
	if c.err != nil {
		return nil, c.err
	}
	return connect.NewResponse(&routerv1.CheckEdgeLeasesResponse{
		Leases: map[string]*routerv1.EdgeLease{
			"p1": {Deadline: timestamppb.New(at), BytesRemaining: 7},
			"p2": {BytesRemaining: 8},
		},
		RevokedPreviewIds: []string{"v1"},
	}), nil
}

type egressClient struct {
	routerv1connect.EgressServiceClient
	got *routerv1.CheckEgressLeasesRequest
}

func (c *egressClient) CheckEgressLeases(
	_ context.Context, req *connect.Request[routerv1.CheckEgressLeasesRequest],
) (*connect.Response[routerv1.CheckEgressLeasesResponse], error) {
	c.got = req.Msg
	return connect.NewResponse(&routerv1.CheckEgressLeasesResponse{
		Leases: map[string]*routerv1.EgressLease{
			"p1": {Deadline: timestamppb.New(at), BytesRemaining: 9, SecretsVersion: 3},
		},
	}), nil
}

func TestEdgeCheckMapsTheCall(t *testing.T) {
	c := &edgeClient{}
	out, err := EdgeCheck(c)(t.Context(), CheckIn{
		Placements: []string{"p1", "p2"},
		Held:       []HeldPreview{{ID: "v1", Generation: 2}, {ID: "v2", Generation: 1}},
	})
	eq(t, err, nil)
	eq(t, c.got.GetPlacementIds(), []string{"p1", "p2"})
	eq(t, len(c.got.GetPreviews()), 2)
	eq(t, c.got.GetPreviews()[0].GetPreviewId(), "v1")
	eq(t, c.got.GetPreviews()[0].GetGeneration(), uint32(2))
	eq(t, c.got.GetPreviews()[1].GetPreviewId(), "v2")
	// A lease without a deadline reads as ended
	eq(t, out, CheckOut{
		States:  map[string]State{"p1": {Deadline: at, Remaining: 7}},
		Revoked: []string{"v1"},
	})

	c.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	_, err = EdgeCheck(c)(t.Context(), CheckIn{Placements: []string{"p1"}})
	eq(t, connect.CodeOf(err), connect.CodeUnavailable)
}

func TestEgressCheckMapsVersions(t *testing.T) {
	c := &egressClient{}
	out, err := EgressCheck(c)(t.Context(), CheckIn{Placements: []string{"p1", "p3"}})
	eq(t, err, nil)
	eq(t, c.got.GetPlacementIds(), []string{"p1", "p3"})
	eq(t, out, CheckOut{
		States: map[string]State{"p1": {Deadline: at, Remaining: 9, SecretsVersion: 3}},
	})
}
