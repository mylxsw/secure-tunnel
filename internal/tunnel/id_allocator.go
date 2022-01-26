//
//   date  : 2015-08-31
//   author: xjdrew
//
package tunnel

type IDAllocator struct {
	freeList chan uint16
}

func (alloc *IDAllocator) Acquire() uint16 {
	return <-alloc.freeList
}

func (alloc *IDAllocator) Release(id uint16) {
	alloc.freeList <- id
}

func newIDAllocator() *IDAllocator {
	freeList := make(chan uint16, MaxID)
	var id uint16
	for id = 1; id != MaxID; id++ {
		freeList <- id
	}
	return &IDAllocator{freeList: freeList}
}
