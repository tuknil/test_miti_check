package main

// substrate_inmemory.go stands the protected target up as an in-process HTTP
// server inside the API container (mode "inmemory") — no docker.sock, no external
// container, no cloud, no network egress. The in-memory WAF (unchanged) sits in
// front of it, so the full bring-up → WAF → test → verdict runs entirely
// in-process, in milliseconds.
//
// Fidelity note: the target is a lightweight stand-in, not the real CVE image.
// For WAF block/pass logic the verdict is equivalent (a blocked request never
// reaches the target; a non-blocked one only needs the target to answer), but it
// is a weaker proof than the local/aci substrates — it validates rule logic, not
// the real vulnerable binary.

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"time"
)

// bringUpInMemorySubstrate starts the in-process stand-in target on a loopback
// port and returns it as the substrate.
func bringUpInMemorySubstrate(ctx context.Context, out *RunOutcome, sub SubstrateSpec, runID string) (*substrate, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "could not start in-memory substrate: " + err.Error()
	}
	srv := &http.Server{Handler: http.HandlerFunc(inMemoryApp)}
	go func() { _ = srv.Serve(ln) }()

	port := ln.Addr().(*net.TCPAddr).Port
	base := "http://127.0.0.1:" + strconv.Itoa(port)
	out.Substrate.ContainerID = "in-process"
	out.Substrate.HostPort = port
	out.Steps = append(out.Steps, "started in-memory substrate (stand-in for "+sub.Image+") at "+base)

	cleanup := func() {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}
	return &substrate{base: base, cleanup: cleanup}, ""
}

// inMemoryApp mimics the protected app: a benign 200 response. Requests only
// reach it when the WAF did not block them.
func inMemoryApp(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Hello, world! (in-memory substrate)\n"))
}
