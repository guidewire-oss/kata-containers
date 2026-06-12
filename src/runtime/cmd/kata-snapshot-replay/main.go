// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

// kata-snapshot-replay drives the destination side of a snapshot
// restore by speaking the MigrationCoordinator protocol in place of a
// source shim.
//
// A live migration has a source shim that dials the destination's
// coordinator and performs PrepareIncoming → SendSandboxState →
// (QEMU stream) → CompleteHandoff. A snapshot restore has no source —
// the VM state lives in files written by /migration/save. This tool
// replays the control-plane half of that conversation from those
// files; the caller streams the saved VM state to the IncomingUri
// between `prepare` and `complete`.
//
// Subcommands:
//
//	prepare  --sandbox-id <id> --state <file> [--coordinator <target>]
//	         PrepareIncoming + SendSandboxState. Prints
//	         {"incomingUri":"tcp:0.0.0.0:<port>"} on stdout — the
//	         caller rewrites the host to an address that reaches the
//	         destination QEMU (it binds inside the sandbox netns) and
//	         streams the saved state to it.
//	complete --sandbox-id <id> [--coordinator <target>]
//	         CompleteHandoff — flips the destination to owner once the
//	         stream has been consumed and QEMU reports completion.
//	abort    --sandbox-id <id> --reason <text> [--coordinator <target>]
//	         AbortHandoff — tears the incoming destination down.
//
// --coordinator defaults to the deterministic per-sandbox unix socket
// (the same one a source shim would dial), so an on-node caller only
// needs the sandbox ID.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	mc "github.com/kata-containers/kata-containers/src/runtime/pkg/containerd-shim-v2/migration_coordinator"
)

const dialTimeout = 30 * time.Second

func main() {
	if len(os.Args) < 2 {
		fail("usage: kata-snapshot-replay <prepare|complete|abort> [flags]")
	}
	cmd, args := os.Args[1], os.Args[2:]

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	sandboxID := fs.String("sandbox-id", "", "destination sandbox ID (required)")
	coordinator := fs.String("coordinator", "", "coordinator target (unix socket path or tcp:host:port); defaults to the sandbox's deterministic socket")
	stateFile := fs.String("state", "", "serialized sandbox-state file from /migration/save (prepare only)")
	reason := fs.String("reason", "snapshot restore aborted", "abort reason (abort only)")
	_ = fs.Parse(args)

	if *sandboxID == "" {
		fail("--sandbox-id is required")
	}
	target := *coordinator
	if target == "" {
		target = mc.SocketPath(*sandboxID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	client, err := mc.Dial(ctx, *sandboxID, target)
	if err != nil {
		fail("dial coordinator %s: %v", target, err)
	}
	defer client.Close()

	switch cmd {
	case "prepare":
		if *stateFile == "" {
			fail("--state is required for prepare")
		}
		// No capabilities: snapshots are written on the single default
		// migration channel (multifd is not file-replayable), so the
		// restore must run plain too.
		prep, err := client.PrepareIncoming(ctx, nil, nil)
		if err != nil {
			fail("PrepareIncoming: %v", err)
		}
		f, err := os.Open(*stateFile)
		if err != nil {
			fail("open state file: %v", err)
		}
		defer f.Close()
		if _, err := client.SendSandboxState(ctx, f); err != nil {
			fail("SendSandboxState: %v", err)
		}
		out, _ := json.Marshal(map[string]string{"incomingUri": prep.IncomingUri})
		fmt.Println(string(out))
	case "complete":
		if _, err := client.CompleteHandoff(ctx); err != nil {
			fail("CompleteHandoff: %v", err)
		}
		fmt.Println(`{"completed":true}`)
	case "abort":
		if err := client.AbortHandoff(ctx, *reason); err != nil {
			fail("AbortHandoff: %v", err)
		}
		fmt.Println(`{"aborted":true}`)
	default:
		fail("unknown subcommand %q (want prepare, complete, or abort)", cmd)
	}
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
