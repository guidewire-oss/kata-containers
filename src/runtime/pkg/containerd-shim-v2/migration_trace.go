// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Config-gated migration trace. The migration failure modes we chase (multifd
// QMP wedge, "exiting QMP loop", fast aborts) happen inside the shim, but the
// shim's logs are hard to reach on locked-down clusters (no node journal, muted
// kubectl debug). This ring buffer records timestamped migration breadcrumbs in
// memory and is surfaced over the agent-reachable HTTP API (/migration/status,
// field "trace"), so an operator can SEE the sequence without node access.
//
// OFF by default — effectively free. The kata shim is spawned by containerd on
// the host (NOT inside the kata-deploy pod), so a pod env var can't reach it.
// Enable in either of two ways, evaluated once at shim start:
//   1. marker file MigrationTraceMarkerPath ("/opt/kata/migration-trace") on the
//      host — this is what `scripts/build.sh kata-migration-image` bakes into the
//      image, so that build turns tracing on with no extra steps. Delete the file
//      on a node (and recycle its pods) to turn it off.
//   2. env KATA_MIGRATION_TRACE=1 in the shim's own process env (i.e. containerd's
//      env), for ad-hoc host debugging.
// Future: wire to a kata configuration.toml option / pod annotation for per-venv control.
//
// Intentionally lock-light and bounded: a single mutex, a fixed ring, no I/O on
// the hot path beyond a timestamp + sprintf.

// MigrationTraceMarkerPath: presence enables tracing. Baked by the migration image build.
const MigrationTraceMarkerPath = "/opt/kata/migration-trace"

const migTraceRingSize = 256

func migTraceInitEnabled() bool {
	if os.Getenv("KATA_MIGRATION_TRACE") == "1" {
		return true
	}
	if _, err := os.Stat(MigrationTraceMarkerPath); err == nil {
		return true
	}
	return false
}

var (
	migTraceEnabled = migTraceInitEnabled()
	migTraceMu      sync.Mutex
	migTraceRing    [migTraceRingSize]string
	migTraceNext    int
	migTraceCount   int
)

// MigrationTraceEnabled reports whether migration tracing is on.
func MigrationTraceEnabled() bool { return migTraceEnabled }

// migTrace appends a timestamped breadcrumb when tracing is enabled. Safe to
// call from any goroutine on the migration path.
func migTrace(format string, args ...interface{}) {
	if !migTraceEnabled {
		return
	}
	line := time.Now().UTC().Format("15:04:05.000Z") + " " + fmt.Sprintf(format, args...)
	migTraceMu.Lock()
	migTraceRing[migTraceNext] = line
	migTraceNext = (migTraceNext + 1) % migTraceRingSize
	if migTraceCount < migTraceRingSize {
		migTraceCount++
	}
	migTraceMu.Unlock()
}

// MigrationTraceSnapshot returns the recorded breadcrumbs oldest-first. Empty
// when tracing is disabled or nothing has been recorded. The migration HTTP
// status handler embeds this as the "trace" field when tracing is on.
func MigrationTraceSnapshot() []string {
	migTraceMu.Lock()
	defer migTraceMu.Unlock()
	out := make([]string, 0, migTraceCount)
	start := (migTraceNext - migTraceCount + migTraceRingSize) % migTraceRingSize
	for i := 0; i < migTraceCount; i++ {
		out = append(out, migTraceRing[(start+i)%migTraceRingSize])
	}
	return out
}
