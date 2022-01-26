//
//   date  : 2014-06-04
//   author: xjdrew
//

package tunnel

import "github.com/mylxsw/asteria/log"

func Recover() {
	if err := recover(); err != nil {
		log.Errorf("goroutine failed:%v", err)
	}
}
