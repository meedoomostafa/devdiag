package main

import (
	"net"
	"os"
	"os/exec"
	"time"
)

func main() {
	_, _ = os.Open("/tmp/devdiag-ebpf-missing-file")
	_ = exec.Command("/tmp/devdiag-ebpf-missing-exec").Run()
	triggerConnectRefused()
	triggerAddressInUse()
}

func triggerConnectRefused() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
	}
}

func triggerAddressInUse() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer listener.Close()
	second, err := net.Listen("tcp", listener.Addr().String())
	if err == nil {
		_ = second.Close()
	}
}
