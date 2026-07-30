package health

import "sync/atomic"

type Gate struct {
	ready atomic.Bool
}

func (g *Gate) Ready() bool {
	return g.ready.Load()
}

func (g *Gate) MarkReady() {
	g.ready.Store(true)
}

func (g *Gate) MarkNotReady() {
	g.ready.Store(false)
}
