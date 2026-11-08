package x402

import (
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
)

// placeEvents is one placement's rows waiting to be sent and its open fold windows
type placeEvents struct {
	queue []*eventRow
	// fresh counts the rows in queue never sent
	fresh int
	// windows holds each open window's folded row, nil until the window's second call
	windows map[foldKey]*routerv1.X402Event
	// names holds each minute's refused_host names by the minute's start
	names map[int64]*nameWindow
}

// foldKey is XS 6.14's fold key within one UTC minute
type foldKey struct {
	host, serviceID, status, reason string
	minute                          int64
}

// nameWindow is one minute's refused_host names and the empty-host row the rest fold into
type nameWindow struct {
	seen map[string]bool
	rest *routerv1.X402Event
}

// eventRow is a queued row and its failed sends
type eventRow struct {
	ev    *routerv1.X402Event
	money bool
	tries int
	// failedAt is a money row's first failed send
	failedAt time.Time
}

// minuteOf is the start of at's UTC minute in Unix seconds
func minuteOf(at time.Time) int64 {
	return at.Truncate(time.Minute).Unix()
}

func keyOf(ev *routerv1.X402Event) foldKey {
	return foldKey{
		host: ev.Host, serviceID: ev.ServiceId, status: ev.Status, reason: ev.Reason,
		minute: minuteOf(ev.At.AsTime()),
	}
}

// place is a placement's entry, made when missing, with e.mu held
func (e *Events) place(placement string) *placeEvents {
	p := e.places[placement]
	if p == nil {
		p = &placeEvents{windows: map[foldKey]*routerv1.X402Event{}, names: map[int64]*nameWindow{}}
		e.places[placement] = p
	}
	return p
}

// tidy forgets a placement with nothing queued and no open window, with e.mu held
func (e *Events) tidy(placement string) {
	p := e.places[placement]
	if p != nil && len(p.queue) == 0 && len(p.windows) == 0 && len(p.names) == 0 {
		delete(e.places, placement)
	}
}

// enqueue puts a row in the queue and wakes Run once a whole batch was never sent
func (e *Events) enqueue(p *placeEvents, ev *routerv1.X402Event, money bool) {
	p.queue = append(p.queue, &eventRow{ev: ev, money: money})
	p.fresh++
	if p.fresh >= maxBatch {
		select {
		case e.full <- struct{}{}:
		default:
		}
	}
}

// fold queues a window's first call at once and folds its later calls into one row
func (e *Events) fold(placement string, k foldKey, ev *routerv1.X402Event) {
	p := e.place(placement)
	folded, open := p.windows[k]
	switch {
	case !open:
		p.windows[k] = nil
		e.enqueue(p, ev, false)
	case folded == nil:
		p.windows[k] = ev
	default:
		merge(folded, ev)
	}
}

// merge adds one call to a folded row, which keeps its first call's other fields
func merge(folded, ev *routerv1.X402Event) {
	folded.Count = sat(folded.Count, 1)
	folded.BytesOut = sat(folded.BytesOut, ev.BytesOut)
	folded.BytesIn = sat(folded.BytesIn, ev.BytesIn)
	if ev.At.AsTime().After(folded.At.AsTime()) {
		folded.At = ev.At
	}
}

// refused folds a refused_host row under its name, or into the minute's empty-host row
func (e *Events) refused(placement string, named bool, ev *routerv1.X402Event) {
	p := e.place(placement)
	m := minuteOf(ev.At.AsTime())
	w := p.names[m]
	if w == nil {
		w = &nameWindow{seen: map[string]bool{}}
		p.names[m] = w
	}
	if named && (w.seen[ev.Host] || len(w.seen) < maxRefusedNames) {
		w.seen[ev.Host] = true
		e.fold(placement, keyOf(ev), ev)
		return
	}
	ev.Host = ""
	if w.rest == nil {
		w.rest = ev
		return
	}
	merge(w.rest, ev)
}

// closeWindows queues the folded rows of the windows whose minute ended, every window's with all
func (e *Events) closeWindows(now time.Time, all bool) {
	current := minuteOf(now)
	for _, p := range e.places {
		for k, folded := range p.windows {
			if all || k.minute < current {
				if folded != nil {
					e.enqueue(p, folded, false)
				}
				delete(p.windows, k)
			}
		}
		for m, w := range p.names {
			if all || m < current {
				if w.rest != nil {
					e.enqueue(p, w.rest, false)
				}
				delete(p.names, m)
			}
		}
	}
}
