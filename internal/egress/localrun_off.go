//go:build !localrun

package egress

// localrunSettings holds no setting in a normal build, so a [localrun] table is unknown
type localrunSettings struct{}

func (s *Server) applyLocalrun() error { return nil }
