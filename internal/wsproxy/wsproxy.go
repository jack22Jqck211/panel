// Package wsproxy routes a WebSocket upgrade request to a local Xray inbound.
//
// Self-hosted mode runs Xray inside the same container as the panel, listening
// on a loopback port per location. The panel is the only thing exposed to the
// internet, so it has to terminate the public side of the WebSocket itself and
// splice the connection through to Xray.
//
// The pattern is the same one test/harness/frontdoor already proved out:
// hijack the underlying TCP socket from the ResponseWriter, replay the original
// HTTP request to the upstream verbatim (so Xray sees the Upgrade and
// Sec-WebSocket-* headers), then bidirectionally copy bytes. There is no need
// to parse the WebSocket protocol itself -- once the upgrade completes, both
// sides are just TCP.
package wsproxy

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
)

// Proxy returns a handler that splices the client connection to the Xray
// inbound listening on 127.0.0.1:port.
//
// The handler is path-agnostic: the caller picks the port based on the path,
// so the same handler shape is reused for every location.
func Proxy(port int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		upstream, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer upstream.Close()

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "cannot hijack", http.StatusInternalServerError)
			return
		}
		client, _, err := hj.Hijack()
		if err != nil {
			// The client already went away or the connection is in a state
			// where hijacking is impossible. Nothing useful to do.
			return
		}
		defer client.Close()

		// Replay the original request verbatim. Xray needs to see the full
		// upgrade handshake -- Connection, Upgrade, Sec-WebSocket-Key, the
		// path with its query -- exactly as the client sent it, otherwise it
		// will not answer with 101 Switching Protocols.
		if err := r.Write(upstream); err != nil {
			return
		}

		// Bidirectional copy. Once the upgrade response has been forwarded
		// (which io.Copy will do as soon as Xray writes it), both sides are
		// raw TCP and we just keep shoveling bytes until one side closes.
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = io.Copy(upstream, client) }()
		go func() { defer wg.Done(); _, _ = io.Copy(client, upstream) }()
		wg.Wait()
	}
}

// IsWebSocketUpgrade reports whether r is a WebSocket handshake request.
//
// VLESS and VMess clients always send Connection: Upgrade and Upgrade:
// websocket; panel requests never do. This check is what lets the panel
// cheaply decide whether to forward a /ws/<cc> path to Xray or handle it as
// an ordinary panel request.
func IsWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	return r.Header.Get("Upgrade") == "websocket" &&
		r.Header.Get("Connection") != ""
}
