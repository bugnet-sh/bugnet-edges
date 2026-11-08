package events

import (
	"context"
	"io"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
)

// EdgeEvents opens WatchEdgeEvents
func EdgeEvents(c routerv1connect.EdgeServiceClient) Open {
	return func(ctx context.Context, cursor string) (Stream, error) {
		s, err := c.WatchEdgeEvents(ctx,
			connect.NewRequest(&routerv1.WatchEdgeEventsRequest{Cursor: cursor}))
		if err != nil {
			return nil, err
		}
		return wrap(s), nil
	}
}

// SSHEvents opens WatchSshEvents
func SSHEvents(c routerv1connect.SshGatewayServiceClient) Open {
	return func(ctx context.Context, cursor string) (Stream, error) {
		s, err := c.WatchSshEvents(ctx,
			connect.NewRequest(&routerv1.WatchSshEventsRequest{Cursor: cursor}))
		if err != nil {
			return nil, err
		}
		return wrap(s), nil
	}
}

// EgressEvents opens WatchEgressEvents
func EgressEvents(c routerv1connect.EgressServiceClient) Open {
	return func(ctx context.Context, cursor string) (Stream, error) {
		s, err := c.WatchEgressEvents(ctx,
			connect.NewRequest(&routerv1.WatchEgressEventsRequest{Cursor: cursor}))
		if err != nil {
			return nil, err
		}
		return wrap(s), nil
	}
}

// watchAnswer is what the three Watch*EventsResponse messages share
type watchAnswer interface {
	GetCursor() string
	GetEvent() *routerv1.EdgeEvent
}

// wrap reads a Watch*Events stream through its shared cursor and event fields
func wrap[T any, P interface {
	*T
	watchAnswer
}](s *connect.ServerStreamForClient[T]) Stream {
	return connectStream[T, P]{s}
}

type connectStream[T any, P interface {
	*T
	watchAnswer
}] struct {
	s *connect.ServerStreamForClient[T]
}

func (c connectStream[T, P]) Recv() (string, *routerv1.EdgeEvent, error) {
	if !c.s.Receive() {
		if err := c.s.Err(); err != nil {
			return "", nil, err
		}
		return "", nil, io.EOF
	}
	m := P(c.s.Msg())
	return m.GetCursor(), m.GetEvent(), nil
}

func (c connectStream[T, P]) Close() error {
	return c.s.Close()
}
