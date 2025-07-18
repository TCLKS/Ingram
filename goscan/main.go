package main

import (
	"flag"
	"fmt"
	"net"
	"sync"
	"time"
)

func main() {
	timeout := flag.Int("timeout", 1, "timeout in seconds")
	concurrency := flag.Int("c", 100, "concurrency")
	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("Usage: go_port_scan [options] ip port1 port2 ...")
		return
	}
	ip := args[0]
	ports := args[1:]

	portCh := make(chan string, len(ports))
	resultCh := make(chan string, len(ports))
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portCh {
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), time.Duration(*timeout)*time.Second)
				if err == nil {
					conn.Close()
					resultCh <- port
				}
			}
		}()
	}

	for _, p := range ports {
		portCh <- p
	}
	close(portCh)

	wg.Wait()
	close(resultCh)
	for p := range resultCh {
		fmt.Printf("%s:%s\n", ip, p)
	}
}
