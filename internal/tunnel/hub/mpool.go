package hub

import (
	"sync"
)

type pool struct {
	*sync.Pool
	sz int
}

func (p *pool) Get() []byte {
	return p.Pool.Get().([]byte)
}

func (p *pool) Put(x []byte) {
	if cap(x) == p.sz {
		p.Pool.Put(x[0:p.sz])
	}
}

func newPool(sz int) *pool {
	p := &pool{sz: sz}
	p.Pool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, p.sz)
		},
	}
	return p
}
