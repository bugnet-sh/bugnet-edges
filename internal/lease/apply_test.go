package lease

import (
	"testing"
	"testing/synctest"
	"time"

	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestApplyEndsMovesAndRevokes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		table := run(t, c)
		deadline := time.Now().Add(time.Hour)
		put := func(id string) *Lease {
			return table.Put(id, State{Deadline: deadline, Remaining: gib, SecretsVersion: 4})
		}
		stopped, expired, moved, spent, other := put("s"), put("x"), put("m"), put("b"), put("o")

		edge := routerv1.BudgetKind_BUDGET_KIND_EDGE
		table.Apply(&routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_PlacementEnded{
			PlacementEnded: &routerv1.PlacementEnded{
				PlacementId: "s", Reason: routerv1.EndReason_END_REASON_STOPPED,
			},
		}}, edge)
		table.Apply(&routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_PlacementEnded{
			PlacementEnded: &routerv1.PlacementEnded{
				PlacementId: "x", Reason: routerv1.EndReason_END_REASON_EXPIRED,
			},
		}}, edge)
		eq(t, stopped.Reason(), ReasonEnded)
		eq(t, expired.Reason(), ReasonExpired)

		later := deadline.Add(time.Hour).UTC()
		dm := &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_DeadlineMoved{
			DeadlineMoved: &routerv1.DeadlineMoved{
				PlacementId: "m", Deadline: timestamppb.New(later),
				EdgeBytesRemaining: 11, EgressBytesRemaining: 22,
			},
		}}
		table.Apply(dm, edge)
		eq(t, moved.State(), State{Deadline: later, Remaining: 11, SecretsVersion: 4})
		table.Apply(dm, routerv1.BudgetKind_BUDGET_KIND_EGRESS)
		eq(t, moved.State(), State{Deadline: later, Remaining: 22, SecretsVersion: 4})
		table.Apply(&routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_DeadlineMoved{
			DeadlineMoved: &routerv1.DeadlineMoved{PlacementId: "m", EdgeBytesRemaining: 1},
		}}, edge)
		eq(t, moved.State().Remaining, uint64(22))

		a, _ := other.Preview(HeldPreview{ID: "pa", Generation: 1})
		b, _ := other.Preview(HeldPreview{ID: "pb", Generation: 1})
		table.Apply(&routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_PreviewRevoked{
			PreviewRevoked: &routerv1.PreviewRevoked{PlacementId: "o", PreviewId: "pa"},
		}}, edge)
		eq(t, Reason(a), ReasonRevoked)
		eq(t, b.Err(), nil)

		egressSpent := &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_BudgetSpent{
			BudgetSpent: &routerv1.BudgetSpent{
				PlacementId: "b", Kind: routerv1.BudgetKind_BUDGET_KIND_EGRESS,
			},
		}}
		table.Apply(egressSpent, edge)
		eq(t, spent.Context().Err(), nil)
		table.Apply(egressSpent, routerv1.BudgetKind_BUDGET_KIND_EGRESS)
		eq(t, spent.Reason(), ReasonBudget)

		table.Apply(&routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_SecretsChanged{
			SecretsChanged: &routerv1.SecretsChanged{PlacementId: "o"},
		}}, edge)
		table.Apply(&routerv1.EdgeEvent{}, edge)
		eq(t, other.Context().Err(), nil)

		c.out = CheckOut{States: live(later, "m", "o")}
		table.Apply(&routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_Resync{
			Resync: &routerv1.Resync{},
		}}, edge)
		synctest.Wait()
		eq(t, c.last(t).Placements, []string{"m", "o"})
	})
}
