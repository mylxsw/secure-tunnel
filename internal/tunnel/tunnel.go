//
//   date  : 2014-06-04
//   author: xjdrew
//

package tunnel

import (
	"time"
)

const (
	MaxID = ^uint16(0)

	PacketSize      = 8192
	KeepalivePeriod = time.Second * 180

	defaultHeartbeat = 1
	tunnelMinSpan    = 3 // 3次心跳无回应则断开
)

var (
	// Heartbeat interval for tunnel heartbeat, seconds.
	Heartbeat int = 1 // seconds

	// Timeout for tunnel write/read, seconds
	Timeout int = 0 //
	mpool       = NewMPool(PacketSize)
)

func getHeartbeat() time.Duration {
	if Heartbeat <= 0 {
		Heartbeat = defaultHeartbeat
	}
	return time.Duration(Heartbeat) * time.Second
}

func getTimeout() time.Duration {
	return time.Duration(Timeout) * time.Second
}
