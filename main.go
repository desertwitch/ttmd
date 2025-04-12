/*
ttmd - A robust HTTP backend for handling TTM connections

ttmd provides a lightweight HTTP server that manages websocket connections for
the TTM (Tmux Terminal Manager) frontend. It features configurable CSRF
authentication, connection lifetime handling with respective resource cleanup,
as well as an optional internal-only mode to restrict access to localhost.

The server attaches to and manages Tmux sessions, providing websocket
connectivity to requested terminal sessions with proper input/output handling,
terminal resizing capabilities, as well as overall connection monitoring.

Please note that this program is only meant to be used in conjunction with the
Tmux Terminal Manager (TTM) frontend on sufficiently secured Unraid data storage
systems within sufficiently secured networking environments without warranties.

Usage:

	ttmd [flags]

The flags are:

	-internal
	    Allow only connections from 127.0.0.1. When this flag is enabled,
	    the server will only accept connections from the local machine,
	    providing an additional layer of security.
	    Default: false

	-csrf
	    Enable CSRF authentication mechanism. When enabled, all connections
	    require a valid CSRF token for authentication.
	    Default: true

	-port string
	    Port to run the server on. Must be a valid numeric port.
	    Default: "49161"

The server handles connections at the following endpoints:

	/
	  Root endpoint for connections.

	/session/{session}
	  Endpoint for a specific session, without CSRF token.

	/session/{session}/csrf/{csrf}
	  Endpoint for a specific session, with provided CSRF token.

Parameters can be provided by request (GET) or as part of the endpoint path.

After validation, connections are upgraded to websockets and authenticated based
on the configuration flags before establishing the terminal session.
*/
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/lmittmann/tint"
)

const (
	// mainGoExitTimeout is the timeout program exit will wait for active
	// connections to finish their resource cleanup.
	mainGoExitTimeout = 45 * time.Second

	// mainSrvExitTimeout is the timeout program exit will wait for HTTP server
	// shutdown itself.
	mainSrvExitTimeout = 20 * time.Second

	// mainStackTraceBuf is the buffer size for any stack trace produced by
	// means of the SIGUSR1 signal.
	mainStackTraceBuf = 1 << 24
)

var (
	// Version is the program's version, as set by the build process.
	Version string

	// addr is the address that the HTTP server is listening on.
	addr string

	// csrfAuthenticator is a token-based [Authenticator].
	csrfAuthenticator *Authenticator

	internalServer = flag.Bool("internal", false, "Allow only connections from 127.0.0.1")
	csrfChecking   = flag.Bool("csrf", true, "Enable CSRF authentication mechanism")
	port           = flag.String("port", "49161", "Port to run the server on")
)

// parseArgs parses the program's command-line arguments.
func parseArgs(ctx context.Context) error {
	flag.Parse()

	if _, err := strconv.Atoi(*port); err != nil {
		return fmt.Errorf("(parseArgs) %w", errArgPortNotNumeric)
	}

	if *internalServer {
		addr = "127.0.0.1:" + *port
		slog.Info("Internal mode - port closed to external connections")
	} else {
		addr = ":" + *port
	}

	if *csrfChecking {
		slog.Info("CSRF authentication mechanism was enabled")
		csrfAuthenticator = NewAuthenticator(ctx)
	} else {
		slog.Info("CSRF authentication mechanism was disabled")
	}

	return nil
}

// setupRouter returns a [mux.Router] configured for TTM's endpoint routes.
func setupRouter(ctx context.Context, wg *sync.WaitGroup, csrfAuthenticator *Authenticator) *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/session/{session}/csrf/{csrf}", func(w http.ResponseWriter, r *http.Request) {
		conn := NewConnection(r, w, csrfAuthenticator)

		wg.Add(1)
		defer wg.Done()

		if err := conn.Handle(ctx); err != nil {
			slog.Error("Incoming connection aborted",
				"err", err,
			)
		}
	})

	r.HandleFunc("/session/{session}", func(w http.ResponseWriter, r *http.Request) {
		conn := NewConnection(r, w, csrfAuthenticator)

		wg.Add(1)
		defer wg.Done()

		if err := conn.Handle(ctx); err != nil {
			slog.Error("Incoming connection aborted",
				"err", err,
			)
		}
	})

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn := NewConnection(r, w, csrfAuthenticator)

		wg.Add(1)
		defer wg.Done()

		if err := conn.Handle(ctx); err != nil {
			slog.Error("Incoming connection aborted",
				"err", err,
			)
		}
	})

	return r
}

// startServer starts the HTTP server.
func startServer(router *mux.Router, addr string) *http.Server {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("FATAL: Failed to start the server",
			"err", err,
			"addr", addr,
		)
		os.Exit(1)
	}

	srv := &http.Server{Addr: addr, Handler: router} //nolint:gosec

	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("FATAL: HTTP server failure",
				"err", err,
			)
			os.Exit(1)
		}
	}()

	slog.Info("Server has started and is listening for connections",
		"addr", addr,
	)

	return srv
}

// shutdownServer handles shutdown of the server and following program exit.
func shutdownServer(cancel context.CancelFunc, wg *sync.WaitGroup, srv *http.Server) {
	slog.Info("Shutting down the server...")

	cancel()

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		slog.Info("All cleanup tasks have completed")
	case <-time.After(mainGoExitTimeout):
		slog.Warn("Timed out waiting for cleanup tasks to complete")
	}

	if csrfAuthenticator != nil {
		csrfAuthenticator.Stop()
	}

	ctxSrv, cancelSrv := context.WithTimeout(context.Background(), mainSrvExitTimeout)
	defer cancelSrv()
	if err := srv.Shutdown(ctxSrv); err != nil {
		slog.Error("Server shutdown has failed",
			"err", err,
		)
	} else {
		slog.Info("Server shutdown was completed")
	}

	slog.Info("Program is exiting - bye for now")
}

func main() {
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slog.SetDefault(slog.New(tint.NewHandler(os.Stdout, &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: time.RFC822,
	})))

	slog.Info("ttmd",
		"version", Version,
	)

	if err := parseArgs(ctx); err != nil {
		slog.Error("FATAL: Failed parsing the command-line arguments",
			"err", err,
		)

		return
	}

	r := setupRouter(ctx, &wg, csrfAuthenticator)
	srv := startServer(r, addr)

	sigChan1 := make(chan os.Signal, 1)
	signal.Notify(sigChan1, syscall.SIGUSR1)
	go func() {
		for range sigChan1 {
			buf := make([]byte, mainStackTraceBuf)
			stacklen := runtime.Stack(buf, true)
			os.Stderr.Write(buf[:stacklen])
		}
	}()

	sigChan2 := make(chan os.Signal, 1)
	signal.Notify(sigChan2, os.Interrupt, syscall.SIGTERM)
	<-sigChan2

	shutdownServer(cancel, &wg, srv)
}
