package common

import (
	"encoding/json"
	"fmt"
	"github.com/shirou/gopsutil/v3/host"
	"net"
	"os"
	"runtime"
	"strings"
)

type SystemInfo struct {
	Version       string   `json:"version"`
	Arch          string   `json:"arch"`
	OS            string   `json:"os"`
	Hostname      string   `json:"hostname"`
	NetInterfaces []string `json:"net_interfaces"`
	Platform      string   `json:"platform"`
	KernelVersion string   `json:"kernel_version"`
}

func (info SystemInfo) Encode() []byte {
	data, _ := json.Marshal(info)
	return data
}

func DecodeSystemInfo(data []byte) *SystemInfo {
	var info SystemInfo
	_ = json.Unmarshal(data, &info)
	return &info
}

func InspectSystemInfo() SystemInfo {
	info := SystemInfo{
		Arch:          runtime.GOARCH,
		OS:            runtime.GOOS,
		NetInterfaces: make([]string, 0),
	}

	info.Hostname, _ = os.Hostname()

	info.NetInterfaces = append(info.NetInterfaces, getOutBoundIP())
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				info.NetInterfaces = append(info.NetInterfaces, ipnet.IP.String())
			}
		}
	}

	hostStat, _ := host.Info()
	info.Platform = fmt.Sprintf("%s %s", hostStat.Platform, hostStat.PlatformVersion)
	info.KernelVersion = hostStat.KernelVersion

	return info
}

func getOutBoundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return strings.Split(localAddr.String(), ":")[0]
}
