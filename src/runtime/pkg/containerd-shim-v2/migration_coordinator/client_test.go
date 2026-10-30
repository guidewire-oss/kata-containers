// Copyright (c) 2026 The Kata Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//

package migration_coordinator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/connectivity"
)

// fakeConn replays a fixed sequence of connectivity states. GetState returns
// the current one; each WaitForStateChange advances to the next, and blocks on
// the context once the sequence is exhausted, the way a real connection does
// when nothing else happens.
type fakeConn struct {
	states   []connectivity.State
	idx      int
	connects int
	waits    int
}

func (f *fakeConn) Connect() { f.connects++ }

func (f *fakeConn) GetState() connectivity.State { return f.states[f.idx] }

func (f *fakeConn) WaitForStateChange(ctx context.Context, _ connectivity.State) bool {
	f.waits++
	if f.idx+1 < len(f.states) {
		f.idx++
		return true
	}
	<-ctx.Done()
	return false
}

func TestWaitForReadyReturnsAtOnceWhenAlreadyReady(t *testing.T) {
	// The race the loop exists for: Ready before the first GetState. The
	// old single wait blocked here until the deadline.
	conn := &fakeConn{states: []connectivity.State{connectivity.Ready}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	assert.NoError(t, waitForReady(ctx, conn))
	assert.Equal(t, 1, conn.connects)
	assert.Equal(t, 0, conn.waits, "an already-Ready connection must not be waited on")
}

func TestWaitForReadyFollowsConnectingToReady(t *testing.T) {
	conn := &fakeConn{states: []connectivity.State{
		connectivity.Idle, connectivity.Connecting, connectivity.Ready,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	assert.NoError(t, waitForReady(ctx, conn))
	assert.Equal(t, 2, conn.waits)
}

func TestWaitForReadyReconnectsFromIdle(t *testing.T) {
	// The channel parks in Idle after a connect attempt that ends without
	// a transport. Idle never changes by itself; the loop must call
	// Connect again instead of waiting on it until the deadline.
	conn := &fakeConn{states: []connectivity.State{
		connectivity.Connecting, connectivity.Idle, connectivity.Connecting, connectivity.Ready,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	assert.NoError(t, waitForReady(ctx, conn))
	assert.Equal(t, 2, conn.connects, "Idle must trigger a second Connect")
}

func TestWaitForReadyReportsTransientFailure(t *testing.T) {
	conn := &fakeConn{states: []connectivity.State{
		connectivity.Connecting, connectivity.TransientFailure,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := waitForReady(ctx, conn)
	assert.ErrorContains(t, err, "transient failure")
}

func TestWaitForReadyReturnsContextErrorWhenStuck(t *testing.T) {
	conn := &fakeConn{states: []connectivity.State{connectivity.Connecting}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	err := waitForReady(ctx, conn)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "got %v", err)
}

func TestDialAgainstRunningServerIsPrompt(t *testing.T) {
	// A real listener over a unix socket, dialled back to back. Before the
	// fix a fraction of these hung for the whole deadline; with it every
	// dial completes in a few milliseconds.
	srv := newTestServer(t, ServerOptions{})
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		start := time.Now()
		c, err := Dial(ctx, srv.SandboxID(), srv.SocketPath())
		cancel()
		if assert.NoError(t, err, "dial %d", i) {
			_ = c.Close()
		}
		assert.Less(t, time.Since(start), time.Second, "dial %d took the deadline path", i)
	}
}
