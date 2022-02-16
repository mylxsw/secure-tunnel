//
//   date  : 2015-06-05
//   author: xjdrew
//

package client

import (
	"github.com/mylxsw/asteria/log"
)

type Item struct {
	*Hub
	Priority int // current Link count
	Index    int // Index in the heap
}

func (h *Item) Status() {
	h.Hub.Status()
	log.Warningf("Priority:%d, Index:%d", h.Priority, h.Index)
}

type Queue []*Item

func (cq Queue) Len() int {
	return len(cq)
}

func (cq Queue) Less(i, j int) bool {
	return cq[i].Priority < cq[j].Priority
}

func (cq Queue) Swap(i, j int) {
	cq[i], cq[j] = cq[j], cq[i]
	cq[i].Index = i
	cq[j].Index = j
}

func (cq *Queue) Push(x interface{}) {
	n := len(*cq)
	hub := x.(*Item)
	hub.Index = n
	*cq = append(*cq, hub)
}

func (cq *Queue) Pop() interface{} {
	old := *cq
	n := len(old)
	hub := old[n-1]
	hub.Index = -1
	*cq = old[0 : n-1]
	return hub
}
