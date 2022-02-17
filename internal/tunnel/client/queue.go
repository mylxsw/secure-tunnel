package client

import (
	"github.com/mylxsw/asteria/log"
)

type queueItem struct {
	*Hub
	priority int // current Link count
	index    int // index in the heap
}

func (h *queueItem) Status() {
	h.Hub.Status()
	log.Warningf("priority: %d, index: %d", h.priority, h.index)
}

type queue []*queueItem

func (cq queue) Len() int {
	return len(cq)
}

func (cq queue) Less(i, j int) bool {
	return cq[i].priority < cq[j].priority
}

func (cq queue) Swap(i, j int) {
	cq[i], cq[j] = cq[j], cq[i]
	cq[i].index = i
	cq[j].index = j
}

func (cq *queue) Push(x interface{}) {
	n := len(*cq)
	hub := x.(*queueItem)
	hub.index = n
	*cq = append(*cq, hub)
}

func (cq *queue) Pop() interface{} {
	old := *cq
	n := len(old)
	hub := old[n-1]
	hub.index = -1
	*cq = old[0 : n-1]
	return hub
}
