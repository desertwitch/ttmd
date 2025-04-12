package ttmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	petname "github.com/dustinkirkland/golang-petname"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

const (
	// connChannelBuffer is the buffer size for the connection buffers.
	connChannelBuffer = 100

	// connCleanTimeout is the time a connection has to cleanup its resources.
	connCleanTimeout = 15 * time.Second

	// connPingPongInterval is the interval at which ping-pong messages are sent
	// to the other end of a websocket connection.
	connPingPongInterval = 30 * time.Second

	// connPingPongTimeout is the time a ping-pong message can take to be
	// delivered to the other end of a websocket connection.
	connPingPongTimeout = 10 * time.Second

	// connPKillTimeout is the time the TTY process can take to exit upon
	// receiving SIGTERM before SIGKILL is sent.
	connPKillTimeout = 10 * time.Second

	// connWriteTimeout is the time a websocket write can take.
	connWriteTimeout = 30 * time.Second
)

// resizeMessage is a JSON control message containing information about the new
// terminal dimensions for the TTY (to be resized accordingly).
type resizeMessage struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// sanitizeInputString does a rudimentary input sanitation of a given input
// string, mainly used for evaluating authentication tokens and session names.
func sanitizeInputString(session string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9_\-$]`)

	return re.ReplaceAllString(session, "")
}

// Connection is the principal implementation of a TTM connection over a
// websocket. It handles the entire lifetime of a TTM session, including
// validations, as well as freeing resources and ensuring appropriate teardown.
// Panics are recovered from, so that other unrelated connections may live.
type Connection struct {
	// request is the respective [http.Request] for the connection.
	request *http.Request

	// requestVars is a [mux.Vars]-created map derived from the [http.Request].
	requestVars map[string]string

	// responseWriter is the [http.ResponseWriter] for the connection.
	responseWriter http.ResponseWriter

	// csrfAuthenticator is an implementation of the CSRF token-based
	// authentication service. If nil is set, no token-based authentication
	// service will be used for the connection.
	csrfAuthenticator *Authenticator

	// cmd is the [exec.Cmd] for the session's TTY process.
	cmd *exec.Cmd

	// ptmx is the [os.File] for the session's TTY descriptor.
	ptmx *os.File

	// websocket is the [websocket.Conn] for the session.
	websocket *websocket.Conn

	// ptmxReads receives all messages read from the TTY. These messages are
	// then written to the websocket.
	ptmxReads chan []byte

	// wsReads receives all messages read from the websocket. These messages are
	// then written to the TTY.
	wsReads chan []byte

	// sessionID is a generated string for better visualization and
	// identification of the connection in the produced logs.
	sessionID string

	// sessionName is the underlying identificator for the Tmux session.
	sessionName atomic.Value

	// isEstablished is set when a connection has been upgraded to a websocket.
	isEstablished atomic.Bool

	// isStarted is set when a connection has been validated and a TTY started.
	isStarted atomic.Bool

	// isCleaned is set when a connection has been completely cleaned up and its
	// resources released at the end of its lifetime.
	isCleaned atomic.Bool

	// wg tracks internally running goroutines.
	wg sync.WaitGroup

	// stateMu protects the connection state information.
	stateMu sync.RWMutex

	// writeMu protects the websocket write operations.
	writeMu sync.Mutex
}

// NewConnection returns a pointer to a new [Connection].
func NewConnection(request *http.Request, responseWriter http.ResponseWriter, csrfAuthenticator *Authenticator) *Connection {
	conn := &Connection{
		sessionID:         petname.Generate(2, "-"), //nolint:mnd
		request:           request,
		requestVars:       mux.Vars(request),
		responseWriter:    responseWriter,
		csrfAuthenticator: csrfAuthenticator,
		ptmxReads:         make(chan []byte, connChannelBuffer),
		wsReads:           make(chan []byte, connChannelBuffer),
	}

	return conn
}

// writeMessage is the thread-safe helper method to write to the websocket. Such
// writes can either be done blocking or non-blocking, while the latter is
// typically used for error messages where delivery can no longer be guaranteed
// and teardown should not wait or be blocked by writing of the (last) message.
func (c *Connection) writeMessage(message []byte, blockingWrite bool) error {
	if blockingWrite {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()

		if ws := c.Websocket(); ws != nil {
			if err := ws.WriteMessage(websocket.BinaryMessage, message); err != nil {
				return fmt.Errorf("(ws) %w", err)
			}

			return nil
		}
	} else {
		go func() {
			c.writeMu.Lock()
			defer c.writeMu.Unlock()

			if ws := c.Websocket(); ws != nil {
				_ = ws.WriteMessage(websocket.BinaryMessage, message)
			}
		}()
	}

	return nil
}

// Name returns the identificator of the Tmux session in a thread-safe manner.
func (c *Connection) Name() string {
	if str, ok := c.sessionName.Load().(string); ok {
		return str
	}

	return ""
}

// Websocket returns the [websocket.Conn] pointer in a thread-safe manner.
func (c *Connection) Websocket() *websocket.Conn {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()

	return c.websocket
}

// Ptmx returns the [os.File] pointer for the TTY in a thread-safe manner.
func (c *Connection) Ptmx() *os.File {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()

	return c.ptmx
}

// Cmd returns the [exec.Cmd] pointer for the TTY in a thread-safe manner.
func (c *Connection) Cmd() *exec.Cmd {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()

	return c.cmd
}

// Handle is the principal method for handling the entire connection's lifetime.
func (c *Connection) Handle(ctx context.Context) (retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			cancel()
			slog.Error("Recovered from panic in connection handler",
				"panic", r,
				"id", c.sessionID,
				"session", c.Name())

			if retErr == nil {
				retErr = fmt.Errorf("(handler) %w", errPanicRecovered)
				go c.destroyAfterPanic(cancel)
			} else {
				retErr = fmt.Errorf("(handler) %w: %w", errPanicRecovered, retErr)
			}
		}
	}()

	defer func() {
		if retErr != nil {
			_ = c.Destroy(cancel)
		}
	}()

	if err := c.Upgrade(ctx, cancel); err != nil {
		return fmt.Errorf("(handle) failed to upgrade connection: %w", err)
	}

	if err := c.Validate(ctx); err != nil {
		return fmt.Errorf("(handle) failed to validate connection: %w", err)
	}

	if err := c.StartTTY(ctx); err != nil {
		return fmt.Errorf("(handle) failed to start connection TTY: %w", err)
	}

	if err := c.StartAgents(ctx, cancel); err != nil {
		return fmt.Errorf("(handle) failed to start connection TTY agents: %w", err)
	}

	slog.Info("Session is now established (and active)",
		"id", c.sessionID,
		"session", c.Name(),
	)

	<-ctx.Done()

	if err := c.Destroy(cancel); err != nil {
		return fmt.Errorf("(handle) failed to destroy connection: %w", err)
	}

	slog.Info("Session is now released (and finished)",
		"id", c.sessionID,
		"session", c.Name(),
	)

	return nil
}

// Upgrade handles upgrading the connection to the respective websocket.
func (c *Connection) Upgrade(ctx context.Context, cancel context.CancelFunc) error {
	if ctx.Err() != nil {
		return fmt.Errorf("(upgrade) %w", ctx.Err())
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true }, //nolint:revive
	}

	ws, err := upgrader.Upgrade(c.responseWriter, c.request, nil)
	if err != nil {
		return fmt.Errorf("(upgrade) failed to upgrade to websocket: %w", err)
	}

	ws.SetCloseHandler(func(code int, text string) error {
		slog.Warn("Websocket was closed by client",
			"code", code,
			"text", text,
			"id", c.sessionID,
			"session", c.Name(),
		)

		cancel()

		return nil
	})

	c.stateMu.Lock()
	c.websocket = ws
	c.stateMu.Unlock()

	c.isEstablished.Store(true)

	return nil
}

// Validate handles validation of the connection, this includes either just
// session identificator input sanitation and/or CSRF authentication token
// validation depending on whether an [Authenticator] was initially provided.
func (c *Connection) Validate(ctx context.Context) error {
	if ctx.Err() != nil {
		return fmt.Errorf("(validate) %w", ctx.Err())
	}

	if c.csrfAuthenticator != nil {
		if err := c.validateToken(ctx); err != nil {
			return fmt.Errorf("(validate) failed token validation: %w", err)
		}
	}
	if err := c.validateSession(ctx); err != nil {
		return fmt.Errorf("(validate) failed session validation: %w", err)
	}

	return nil
}

// validateToken handles CSRF authentication token validation.
func (c *Connection) validateToken(ctx context.Context) error {
	if ctx.Err() != nil {
		return fmt.Errorf("(token) %w", ctx.Err())
	}

	var requestToken string

	if t, ok := c.requestVars["csrf"]; ok {
		requestToken = t
	} else if t := c.request.URL.Query().Get("csrf"); t != "" {
		requestToken = t
	}

	requestToken = sanitizeInputString(requestToken)
	if requestToken == "" {
		_ = c.writeMessage([]byte("Invalid authentication token."), false)

		return fmt.Errorf("(token) %w", errReceivedTokenEmpty)
	}

	actualToken := c.csrfAuthenticator.Token()
	if actualToken == "" || actualToken != requestToken {
		_ = c.writeMessage([]byte("Invalid authentication token."), false)

		return fmt.Errorf("(token) %w", errReceivedTokenMismatch)
	}

	return nil
}

// validateSession handles input session identificator sanitation.
func (c *Connection) validateSession(ctx context.Context) error {
	if ctx.Err() != nil {
		return fmt.Errorf("(session) %w", ctx.Err())
	}

	var sessionName string

	if s, ok := c.requestVars["session"]; ok {
		sessionName = s
	} else if s := c.request.URL.Query().Get("session"); s != "" {
		sessionName = s
	}

	sessionName = sanitizeInputString(sessionName)
	if sessionName == "" {
		_ = c.writeMessage([]byte("Session does not exist."), false)

		return fmt.Errorf("(session) %w", errReceivedSessionEmpty)
	}

	c.sessionName.Store(sessionName)

	return nil
}

// StartTTY starts the TTY for the respective Tmux session.
func (c *Connection) StartTTY(ctx context.Context) error {
	if ctx.Err() != nil {
		return fmt.Errorf("(%s/tty) %w", c.Name(), ctx.Err())
	}

	cmd := exec.Command("tmux", "-u", "new-session", "-A", "-t", c.Name(), "-x", "80", "-y", "24") //nolint:gosec
	cmd.Env = append(cmd.Env,
		"TERM=xterm-256color",
		"LC_ALL=en_US.UTF-8",
		"LANG=en_US.UTF-8",
	)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		_ = c.writeMessage([]byte("Failed to start TTY."), false)

		return fmt.Errorf("(%s/tty) failed to start TTY: %w", c.Name(), err)
	}

	c.stateMu.Lock()
	c.cmd = cmd
	c.ptmx = ptmx
	c.stateMu.Unlock()

	c.isStarted.Store(true)

	return nil
}

// StartAgents starts the I/O agents for all I/O of the connection.
func (c *Connection) StartAgents(ctx context.Context, cancel context.CancelFunc) error {
	if ctx.Err() != nil {
		return fmt.Errorf("(%s/agents) %w", c.Name(), ctx.Err())
	}

	c.wg.Add(1)
	go c.ptmxWriter(ctx, cancel)

	c.wg.Add(1)
	go c.wsWriter(ctx, cancel)

	c.wg.Add(1)
	go c.ptmxReader(ctx, cancel)

	c.wg.Add(1)
	go c.wsReader(ctx, cancel)

	c.wg.Add(1)
	go c.wsPingPong(ctx, cancel)

	return nil
}

// wsPingPong handles ping-pongs for the websocket connection.
func (c *Connection) wsPingPong(ctx context.Context, cancel context.CancelFunc) {
	defer func() {
		if r := recover(); r != nil {
			cancel()
			slog.Error("Recovered from panic in WS ping-pong",
				"panic", r,
				"id", c.sessionID,
				"session", c.Name())
		}
		c.wg.Done()
	}()

	ticker := time.NewTicker(connPingPongInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if ws := c.Websocket(); ws != nil {
				if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(connPingPongTimeout)); err != nil {
					slog.Warn("Ping-pong has failed",
						"err", err,
						"id", c.sessionID,
						"session", c.Name(),
					)
					_ = c.writeMessage([]byte("Ping-pong failure - session closed."), false)

					cancel()

					return
				}
			}
		}
	}
}

// wsWriter writes messages read from the TTY to the websocket.
func (c *Connection) wsWriter(ctx context.Context, cancel context.CancelFunc) {
	defer func() {
		if r := recover(); r != nil {
			cancel()
			slog.Error("Recovered from panic in WS writer",
				"panic", r,
				"id", c.sessionID,
				"session", c.Name())
		}
		c.wg.Done()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-c.ptmxReads:
			if ws := c.Websocket(); ws != nil {
				_ = ws.SetWriteDeadline(time.Now().Add(connWriteTimeout))
				if err := c.writeMessage(msg, true); err != nil {
					slog.Warn("Websocket write error",
						"err", err,
						"id", c.sessionID,
						"session", c.Name(),
					)
					_ = c.writeMessage([]byte("Websocket write failure - session closed."), false)
					cancel()

					return
				}
			}
		}
	}
}

// ptmxReader reads messages from the TTY and sends them to the websocket
// writer.
func (c *Connection) ptmxReader(ctx context.Context, cancel context.CancelFunc) {
	defer func() {
		if r := recover(); r != nil {
			cancel()
			slog.Error("Recovered from panic in TTY reader",
				"panic", r,
				"id", c.sessionID,
				"session", c.Name())
		}
		c.wg.Done()
	}()

	buf := make([]byte, 1024) //nolint:mnd
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if ptmx := c.Ptmx(); ptmx != nil {
				n, err := ptmx.Read(buf)
				if err != nil {
					slog.Warn("TTY read error",
						"err", err,
						"id", c.sessionID,
						"session", c.Name(),
					)
					_ = c.writeMessage([]byte("TTY read failure - session closed."), false)

					cancel()

					return
				}

				message := make([]byte, n)
				copy(message, buf[:n])

				select {
				case <-ctx.Done():
					return
				case c.ptmxReads <- message:
				}
			}
		}
	}
}

// ptmxWriter writes messages read from the websocket to the TTY.
func (c *Connection) ptmxWriter(ctx context.Context, cancel context.CancelFunc) {
	defer func() {
		if r := recover(); r != nil {
			cancel()
			slog.Error("Recovered from panic in TTY writer",
				"panic", r,
				"id", c.sessionID,
				"session", c.Name())
		}
		c.wg.Done()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-c.wsReads:
			resizeMessage := &resizeMessage{}
			if err := json.Unmarshal(msg, resizeMessage); err == nil && resizeMessage.Type == "resize" {
				if ptmx := c.Ptmx(); ptmx != nil {
					if err := pty.Setsize(ptmx, &pty.Winsize{
						Cols: resizeMessage.Cols,
						Rows: resizeMessage.Rows,
					}); err != nil {
						slog.Warn("Failed to resize TTY",
							"err", err,
							"id", c.sessionID,
							"session", c.Name(),
						)
					}
				}

				continue
			}

			if ptmx := c.Ptmx(); ptmx != nil {
				if _, err := ptmx.Write(msg); err != nil {
					slog.Warn("TTY write error",
						"err", err,
						"id", c.sessionID,
						"session", c.Name(),
					)
					_ = c.writeMessage([]byte("TTY write failure - session closed."), false)

					cancel()

					return
				}
			}
		}
	}
}

// wsReader reads messages from the websocket and sends them to the TTY writer.
func (c *Connection) wsReader(ctx context.Context, cancel context.CancelFunc) {
	defer func() {
		if r := recover(); r != nil {
			cancel()
			slog.Error("Recovered from panic in WS reader",
				"panic", r,
				"id", c.sessionID,
				"session", c.Name())
		}
		c.wg.Done()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if ws := c.Websocket(); ws != nil {
				_, message, err := ws.ReadMessage()
				if err != nil {
					slog.Warn("Websocket read error",
						"err", err,
						"id", c.sessionID,
						"session", c.Name(),
					)
					_ = c.writeMessage([]byte("Websocket read failure - session closed."), false)

					cancel()

					return
				}

				select {
				case <-ctx.Done():
					return
				case c.wsReads <- message:
				}
			}
		}
	}
}

// destroyAfterPanic is a helper method that asynchronously calls the
// [Connection.Destroy] method as part of panic recovery. Since the state of the
// connection is unknown, destroying it could panic again or deadlock, so we
// risk leaking this as a Goroutine instead and recover any additional panics.
func (c *Connection) destroyAfterPanic(cancel context.CancelFunc) {
	defer func() {
		_ = recover()
	}()
	_ = c.Destroy(cancel)
}

// Destroy handles destruction of a connection. In principal it is idempotent
// and can be called multiple times, as it excludes already cleaned resources.
func (c *Connection) Destroy(cancel context.CancelFunc) error {
	if c.isCleaned.Load() {
		return nil
	}

	cancel()

	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	if ws := c.websocket; ws != nil {
		if err := ws.Close(); err != nil {
			return fmt.Errorf("(%s/destroy) failed to close websocket: %w", c.Name(), err)
		}
		c.websocket = nil
	}

	if ptmx := c.ptmx; ptmx != nil {
		if err := ptmx.Close(); err != nil {
			return fmt.Errorf("(%s/destroy) failed to close tty: %w", c.Name(), err)
		}
		c.ptmx = nil
	}

	if cmd := c.cmd; cmd != nil && cmd.Process != nil {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			slog.Warn("Failed to terminate the TMUX process",
				"err", err,
				"id", c.sessionID,
				"session", c.Name(),
			)
		}

		waitDone := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(waitDone)
		}()

		select {
		case <-waitDone:
		case <-time.After(connPKillTimeout):
			if err := cmd.Process.Kill(); err != nil {
				return fmt.Errorf("(%s/destroy) failed to kill TTY process: %w", c.Name(), err)
			}
		}

		c.cmd = nil
	}

	waitDone := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		c.isCleaned.Store(true)
	case <-time.After(connCleanTimeout):
		slog.Warn("Timed out waiting for the TTY agents to exit",
			"id", c.sessionID,
			"session", c.Name(),
		)
	}

	return nil
}
