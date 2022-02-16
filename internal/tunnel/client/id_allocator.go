package client

const (
	MaxID = ^uint16(0)
)

type idAllocator struct {
	freeList chan uint16
}

func (alloc *idAllocator) Acquire() uint16 {
	return <-alloc.freeList
}

func (alloc *idAllocator) Release(id uint16) {
	alloc.freeList <- id
}

func newIDAllocator() *idAllocator {
	freeList := make(chan uint16, MaxID)
	var id uint16
	for id = 1; id != MaxID; id++ {
		freeList <- id
	}
	return &idAllocator{freeList: freeList}
}
