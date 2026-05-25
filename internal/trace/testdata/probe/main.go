package main

import (
	"net"
	"os"
	"syscall"
)

func main() {
	_, _ = os.Open("/tmp/devdiag-ebpf-missing-file")
	triggerConnectRefused()
	triggerAddressInUse()
	_ = syscall.Exec("/tmp/devdiag-ebpf-missing-exec", []string{"devdiag-ebpf-missing-exec"}, os.Environ())
}

func triggerConnectRefused() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return
	}
	_ = listener.Close()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	_ = syscall.Connect(fd, &syscall.SockaddrInet4{Port: addr.Port, Addr: [4]byte{127, 0, 0, 1}})
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
