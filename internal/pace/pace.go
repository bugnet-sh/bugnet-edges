// Package pace slows each placement's traffic to its pace each way, then to a total per process
package pace

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"
)

// Piece is the most bytes one read or write carries between waits, and every limiter's burst
const Piece = 64 << 10

// ErrDropped ends a read or write whose lane was dropped while it waited
var ErrDropped = errors.New("pace: the placement's lane was dropped")

// Pacer holds one lane per placement and the process-wide cap they share
type Pacer struct {
	total *rate.Limiter

	mu    sync.Mutex
	lanes map[string]*Lane
}

// New caps every lane together at totalBytesPerSecond, both ways, 0 or less is no cap
func New(totalBytesPerSecond int64) *Pacer {
	p := &Pacer{lanes: map[string]*Lane{}}
	if totalBytesPerSecond > 0 {
		p.total = rate.NewLimiter(rate.Limit(totalBytesPerSecond), Piece)
	}
	return p
}

// Lane returns the placement's lane, made unpaced on first use
func (p *Pacer) Lane(placement string) *Lane {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l, ok := p.lanes[placement]; ok {
		return l
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Lane{
		total:  p.total,
		ctx:    ctx,
		cancel: cancel,
		in:     rate.NewLimiter(1, Piece),
		out:    rate.NewLimiter(1, Piece),
	}
	p.lanes[placement] = l
	return l
}

// Drop forgets the placement's lane and ends the reads and writes waiting on it
func (p *Pacer) Drop(placement string) {
	p.mu.Lock()
	l, ok := p.lanes[placement]
	delete(p.lanes, placement)
	p.mu.Unlock()
	if ok {
		l.cancel()
	}
}

// Lane paces one placement, toward the sandbox and from it apart
type Lane struct {
	total   *rate.Limiter
	ctx     context.Context
	cancel  context.CancelFunc
	in, out *rate.Limiter
	// perSecond is 0 while unpaced, so the limiters never see rate.Inf
	perSecond atomic.Int64
}

// SetRate paces each way at bytesPerSecond, 0 or less leaves only the total cap
func (l *Lane) SetRate(bytesPerSecond int64) {
	if bytesPerSecond <= 0 {
		l.perSecond.Store(0)
		return
	}
	l.in.SetLimit(rate.Limit(bytesPerSecond))
	l.out.SetLimit(rate.Limit(bytesPerSecond))
	l.perSecond.Store(bytesPerSecond)
}

// Reader paces reads from r, in is toward the sandbox, count sees each piece once it passed
func (l *Lane) Reader(r io.Reader, in bool, count func(int)) io.Reader {
	return &reader{l: l, r: r, way: l.way(in), count: count}
}

// Writer paces writes to w in pieces, in is toward the sandbox, count sees each piece written
func (l *Lane) Writer(w io.Writer, in bool, count func(int)) io.Writer {
	return &writer{l: l, w: w, way: l.way(in), count: count}
}

func (l *Lane) way(in bool) *rate.Limiter {
	if in {
		return l.in
	}
	return l.out
}

// wait holds n bytes on the lane's limiter for this way, then on the total
func (l *Lane) wait(way *rate.Limiter, n int) error {
	if l.ctx.Err() != nil {
		return ErrDropped
	}
	if l.perSecond.Load() > 0 {
		if err := way.WaitN(l.ctx, n); err != nil {
			return ErrDropped
		}
	}
	if l.total != nil {
		if err := l.total.WaitN(l.ctx, n); err != nil {
			return ErrDropped
		}
	}
	return nil
}

type reader struct {
	l     *Lane
	r     io.Reader
	way   *rate.Limiter
	count func(int)
}

func (x *reader) Read(p []byte) (int, error) {
	if len(p) > Piece {
		p = p[:Piece]
	}
	n, err := x.r.Read(p)
	if n > 0 {
		if werr := x.l.wait(x.way, n); werr != nil {
			return 0, werr
		}
		if x.count != nil {
			x.count(n)
		}
	}
	return n, err
}

type writer struct {
	l     *Lane
	w     io.Writer
	way   *rate.Limiter
	count func(int)
}

func (x *writer) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		piece := p[:min(len(p), Piece)]
		if err := x.l.wait(x.way, len(piece)); err != nil {
			return written, err
		}
		n, err := x.w.Write(piece)
		written += n
		if n > 0 && x.count != nil {
			x.count(n)
		}
		if err != nil {
			return written, err
		}
		if n < len(piece) {
			return written, io.ErrShortWrite
		}
		p = p[n:]
	}
	return written, nil
}
