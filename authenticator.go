package ttmd

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// authExitTimeout is the time that will be waited for the Authenticator to
	// stop it's internal goroutines when calling [Authenticator.Stop].
	authExitTimeout = 5 * time.Second

	// authRetryTime is the interval after which another token update will be
	// performed when experiencing an error during the previous update.
	authRetryTime = 5 * time.Second

	// authUpdateTime is the regular interval after which another token update
	// will be performed when the previous update has succeeded.
	authUpdateTime = 10 * time.Second

	// authStateFile is the system's state file to read the token from.
	authStateFile = "/var/local/emhttp/var.ini"
)

// Authenticator is a token-based authentication service.
type Authenticator struct {
	sync.RWMutex

	token string

	errChan  chan error
	doneChan chan struct{}

	wg sync.WaitGroup
}

// NewAuthenticator returns a pointer to a new [Authenticator]. It starts an
// initial update as well as the periodic updating routine. A deferred call to
// [Authenticator.Stop] should be placed before the program exits.
func NewAuthenticator(ctx context.Context) *Authenticator {
	auth := &Authenticator{
		errChan:  make(chan error, 1),
		doneChan: make(chan struct{}),
	}

	auth.Update(ctx)

	auth.wg.Add(1)
	go auth.periodicUpdate(ctx)

	return auth
}

// Stop signals the authentication service to stop and blocks up to
// [authExitTimeout], waiting for the internal goroutines to finish.
func (auth *Authenticator) Stop() {
	close(auth.doneChan)

	waitChan := make(chan struct{})
	go func() {
		auth.wg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
	case <-time.After(authExitTimeout):
		slog.Warn("Timed out waiting for CSRF authentication agent to exit")
	}
}

// Token returns the current authentication token for reference/comparison.
func (auth *Authenticator) Token() string {
	auth.RLock()
	defer auth.RUnlock()

	return auth.token
}

// Update reads the current authentication token from the system's state file
// and stores it interally for reference/comparing against.
func (auth *Authenticator) Update(ctx context.Context) {
	file, err := os.Open(authStateFile)
	if err != nil {
		select {
		case <-ctx.Done():
			return
		case auth.errChan <- err:
		default:
		}

		slog.Warn("Error opening file",
			"err", err,
			"path", authStateFile,
		)

		return
	}

	var token string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "csrf_token=") {
			token = strings.TrimPrefix(line, "csrf_token=")
			if strings.HasPrefix(token, "\"") && strings.HasSuffix(token, "\"") {
				token = strings.Trim(token, "\"")
			}

			break
		}
	}
	file.Close()

	if err := scanner.Err(); err != nil {
		select {
		case <-ctx.Done():
			return
		case auth.errChan <- err:
		default:
		}

		slog.Warn("Error reading file",
			"err", err,
			"path", authStateFile,
		)

		return
	}

	if token != "" {
		if auth.Token() != token {
			auth.Lock()
			auth.token = token
			auth.Unlock()

			slog.Info("CSRF token was established and stored with success")
		}
	} else {
		slog.Warn("CSRF was token not found in respective file (will retry)")
	}
}

// periodicUpdate updates the authentication token every [authUpdateTime] or, if
// an error occurred during the previous update, every [authRetryTime].
func (auth *Authenticator) periodicUpdate(ctx context.Context) {
	defer func() {
		auth.wg.Done()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-auth.doneChan:
			return
		case <-auth.errChan:
			time.Sleep(authRetryTime)
		case <-time.After(authUpdateTime):
			auth.Update(ctx)
		}
	}
}
