// Command frontdoor stands in for nginx during integration tests.
//
// It does not reimplement a routing policy: it parses the location blocks out of
// the nginx.conf the panel generated and forwards according to that file. So if
// the generated mapping sends /ws/de to the wrong Xray inbound, this harness
// reproduces the mistake instead of hiding it.
//
// This validates the content of the generated config. It does not validate that
// nginx itself parses the file -- `nginx -t` in deploy/agent.sh covers that on
// the real server, before every reload.
//
// Usage: frontdoor <nginx.conf> <listenPort>
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
)

// locationRe captures a location path and the upstream port from its proxy_pass.
var locationRe = regexp.MustCompile(
	`(?s)location\s+(\S+)\s*\{[^}]*?proxy_pass\s+http://127\.0\.0\.1:(\d+)\s*;`)

func main() {
	if len(os.Args) < 3 {
		log.Fatal("usage: frontdoor <nginx.conf> <listenPort>")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("read nginx config: %v", err)
	}

	routes := map[string]int{}
	for _, m := range locationRe.FindAllStringSubmatch(string(raw), -1) {
		port, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		routes[m[1]] = port
	}
	if len(routes) == 0 {
		log.Fatal("no location blocks with a proxy_pass were found in the config")
	}
	fmt.Printf("frontdoor: %d routes parsed from %s\n", len(routes), os.Args[1])

	srv := &http.Server{
		Addr: "127.0.0.1:" + os.Args[2],
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			port, ok := routes[r.URL.Path]
			if !ok {
				// Mirror the generated config's catch-all.
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			proxy(w, r, port)
		}),
	}
	log.Fatal(srv.ListenAndServe())
}

// proxy hijacks the client connection and splices it to the upstream, which is
// what a WebSocket upgrade requires.
func proxy(w http.ResponseWriter, r *http.Request, port int) {
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
		return
	}
	defer client.Close()

	// Replay the request upstream verbatim, preserving the upgrade headers that
	// the real nginx config is careful to forward.
	if err := r.Write(upstream); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(upstream, client) }()
	go func() { defer wg.Done(); io.Copy(client, upstream) }()
	wg.Wait()
}
