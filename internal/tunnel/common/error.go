package common

import (
	"github.com/mylxsw/asteria/log"
	"runtime"
)

func ErrorHandler() {
	if err := recover(); err != nil {
		buf := make([]byte, 32768)
		runtime.Stack(buf, true)

		log.Errorf("goroutine failed: %v, stack: %s", err, string(buf))
	}
}
