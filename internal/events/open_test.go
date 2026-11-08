package events

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
)

// answers is what every fake Watch call sends before it ends
var answers = []struct {
	cursor string
	ev     *routerv1.EdgeEvent
}{{"1-0", ended("p1")}, {"2-0", nil}}

// end ends a fake stream cleanly for the cursor "clean", else with Unavailable
func end(cursor string) error {
	if cursor == "clean" {
		return nil
	}
	return connect.NewError(connect.CodeUnavailable, errors.New("draining"))
}

type edgeHandler struct {
	routerv1connect.UnimplementedEdgeServiceHandler
}

func (edgeHandler) WatchEdgeEvents(
	_ context.Context, req *connect.Request[routerv1.WatchEdgeEventsRequest],
	s *connect.ServerStream[routerv1.WatchEdgeEventsResponse],
) error {
	for _, a := range answers {
		err := s.Send(&routerv1.WatchEdgeEventsResponse{Cursor: a.cursor, Event: a.ev})
		if err != nil {
			return err
		}
	}
	return end(req.Msg.GetCursor())
}

type sshHandler struct {
	routerv1connect.UnimplementedSshGatewayServiceHandler
}

func (sshHandler) WatchSshEvents(
	_ context.Context, req *connect.Request[routerv1.WatchSshEventsRequest],
	s *connect.ServerStream[routerv1.WatchSshEventsResponse],
) error {
	for _, a := range answers {
		err := s.Send(&routerv1.WatchSshEventsResponse{Cursor: a.cursor, Event: a.ev})
		if err != nil {
			return err
		}
	}
	return end(req.Msg.GetCursor())
}

type egressHandler struct {
	routerv1connect.UnimplementedEgressServiceHandler
}

func (egressHandler) WatchEgressEvents(
	_ context.Context, req *connect.Request[routerv1.WatchEgressEventsRequest],
	s *connect.ServerStream[routerv1.WatchEgressEventsResponse],
) error {
	for _, a := range answers {
		err := s.Send(&routerv1.WatchEgressEventsResponse{Cursor: a.cursor, Event: a.ev})
		if err != nil {
			return err
		}
	}
	return end(req.Msg.GetCursor())
}

func TestOpenFollowsEachService(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(routerv1connect.NewEdgeServiceHandler(edgeHandler{}))
	mux.Handle(routerv1connect.NewSshGatewayServiceHandler(sshHandler{}))
	mux.Handle(routerv1connect.NewEgressServiceHandler(egressHandler{}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := srv.Client()

	opens := map[string]Open{
		"edge":   EdgeEvents(routerv1connect.NewEdgeServiceClient(c, srv.URL)),
		"ssh":    SSHEvents(routerv1connect.NewSshGatewayServiceClient(c, srv.URL)),
		"egress": EgressEvents(routerv1connect.NewEgressServiceClient(c, srv.URL)),
	}
	for name, open := range opens {
		t.Run(name, func(t *testing.T) {
			for _, cursor := range []string{"9-0", "clean"} {
				s, err := open(t.Context(), cursor)
				if err != nil {
					t.Fatal(err)
				}
				for _, a := range answers {
					got, ev, err := s.Recv()
					eq(t, err, nil)
					eq(t, got, a.cursor)
					eq(t, ev.GetPlacementEnded().GetPlacementId(),
						a.ev.GetPlacementEnded().GetPlacementId())
				}
				_, _, err = s.Recv()
				if cursor == "clean" {
					eq(t, err, io.EOF)
				} else {
					eq(t, connect.CodeOf(err), connect.CodeUnavailable)
				}
				eq(t, s.Close(), nil)
			}
		})
	}
}
