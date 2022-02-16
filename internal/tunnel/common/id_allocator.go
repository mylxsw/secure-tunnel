package common

const (
	MaxID = ^uint16(0)
)

type IDAllocator struct {
	freeList chan uint16
}

func (alloc *IDAllocator) Acquire() uint16 {
	return <-alloc.freeList
}

func (alloc *IDAllocator) Release(id uint16) {
	alloc.freeList <- id
}

func NewIDAllocator() *IDAllocator {
	freeList := make(chan uint16, MaxID)
	var id uint16
	for id = 1; id != MaxID; id++ {
		freeList <- id
	}
	return &IDAllocator{freeList: freeList}
}
