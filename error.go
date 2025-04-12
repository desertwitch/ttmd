package main

import "errors"

var (
	// errArgPortNotNumeric occurs when a CLI-provided port argument was not
	// numeric.
	errArgPortNotNumeric = errors.New("requested port is not numeric")

	// errPanicRecovered occurs when a panic inside a connection is recovered.
	errPanicRecovered = errors.New("a panic was recovered")

	// errReceivedTokenEmpty occurs when a provided authentication token was
	// empty.
	errReceivedTokenEmpty = errors.New("received token is empty")

	// errReceivedTokenMismatch occurs when the wrong authentication token was
	// provided.
	errReceivedTokenMismatch = errors.New("received token mismatches actual token")

	// errReceivedSessionEmpty occurs when the provided session name is empty
	// (after sanitation).
	errReceivedSessionEmpty = errors.New("received session name is empty")
)
