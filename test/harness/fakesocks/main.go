// Command fakesocks stands in for the 50 Tor instances during integration tests.
//
// It opens a minimal SOCKS5 listener on every port Tor-ML would use
// (48180-48229). Each listener accepts a CONNECT, then -- instead of dialing
// anywhere -- answers with a tiny HTTP response naming the port that handled the
// request.
//
// That substitution is what makes the test meaningful: the response identifies
// which Tor SOCKS port the traffic actually emerged from, so the harness can
// prove that /ws/de left through 48180 and /ws/us through 48182. Getting that
// mapping wrong is the failure mode that would silently hand a user the wrong
// exit country, and it is invisible from the outside.
//
// Tor itself is not simulated -- only its SOCKS front door.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
)

const (
	basePort  = 48180
	numPorts  = 50
	socks5Ver = 0x05
)

func main() {
	base := basePort
	count := numPorts
	if len(os.Args) > 1 {
		if v, err := strconv.Atoi(os.Args[1]); err == nil {
			base = v
		}
	}
	if len(os.Args) > 2 {
		if v, err := strconv.Atoi(os.Args[2]); err == nil {
			count = v
		}
	}

	var wg sync.WaitGroup
	started := 0
	for i := 0; i < count; i++ {
		port := base + i
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			log.Printf("port %d unavailable: %v", port, err)
			continue
		}
		started++
		wg.Add(1)
		go func(ln net.Listener, port int) {
			defer wg.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go serve(conn, port)
			}
		}(ln, port)
	}
	fmt.Printf("fakesocks: %d listeners up (%d-%d)\n", started, base, base+count-1)
	wg.Wait()
}

// serve performs a minimal SOCKS5 negotiation then replies as if it were the
// destination web server.
func serve(conn net.Conn, port int) {
	defer conn.Close()

	// Greeting: version, method count, methods.
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	if head[0] != socks5Ver {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, int(head[1]))); err != nil {
		return
	}
	// Accept, no authentication.
	if _, err := conn.Write([]byte{socks5Ver, 0x00}); err != nil {
		return
	}

	// Request: version, command, reserved, address type.
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	switch req[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
			return
		}
	case 0x03: // domain name, which is what Xray's SOCKS outbound normally sends
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, int(l[0]))); err != nil {
			return
		}
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, make([]byte, 16)); err != nil {
			return
		}
	default:
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil { // port
		return
	}

	// Success, bound to 0.0.0.0:0.
	reply := []byte{socks5Ver, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(reply[8:], 0)
	if _, err := conn.Write(reply); err != nil {
		return
	}

	// Read the tunnelled request and answer with this listener's identity. The
	// body is the whole point: it travels back through Xray to the client, so the
	// test can attribute the request to a specific Tor SOCKS port.
	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	body := fmt.Sprintf("TORPORT=%d\n", port)
	fmt.Fprintf(conn,
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}
