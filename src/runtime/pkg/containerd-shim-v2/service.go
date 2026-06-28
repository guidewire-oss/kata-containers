// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"fmt"
	"io"
	"os"
	sysexec "os/exec"
	goruntime "runtime"
	"sync"
	"syscall"
	"time"

	eventstypes "github.com/containerd/containerd/api/events"
	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/namespaces"
	cdruntime "github.com/containerd/containerd/runtime"
	cdshim "github.com/containerd/containerd/runtime/v2/shim"
	"github.com/containerd/typeurl/v2"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils/katatrace"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/oci"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/utils"
	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/compatoci"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	otelTrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// shimTracingTags defines tags for the trace span
var shimTracingTags = map[string]string{
	"source":  "runtime",
	"package": "containerdshim",
}

const (
	// Define the service's channel size, which is used for
	// reaping the exited processes exit state and forwarding
	// it to containerd as the containerd event format.
	bufferSize = 32

	chSize      = 128
	exitCode255 = 255
)

var (
	empty                     = &emptypb.Empty{}
	_     taskAPI.TaskService = (taskAPI.TaskService)(&service{})
)

// concrete virtcontainer implementation
var vci vc.VC = &vc.VCImpl{}

// shimLog is logger for shim package
var shimLog = logrus.WithFields(logrus.Fields{
	"source": "containerd-kata-shim-v2",
	"name":   "containerd-shim-v2",
})

// shimRPCLog logs entry of a TaskService RPC and returns a function
// to defer-call that records exit with elapsed time and any error.
//
// Why: post-migration we observe containerd's ttrpc to the shim
// closing without diagnostic — the shim process is alive but
// `kubectl exec` fails with "ttrpc: closed". With every RPC bracketed
// by entry/exit logs we can pin down which call preceded the closure
// (Delete? Shutdown? Kill?) and whether the call failed before the
// connection died. Use:
//
//	func (s *service) Foo(...) (_ *Resp, err error) {
//	    defer shimRPCLog("Foo", r.ID)(&err)
//	    ...
//	}
//
// The named-return `err` is required so the deferred closure sees
// the final error value (Go evaluates `&err` at defer-eval time, but
// the pointer dereferences the variable's final state).
func shimRPCLog(method, containerID string) func(errp *error) {
	start := time.Now()
	shimLog.WithFields(logrus.Fields{
		"rpc":       method,
		"container": containerID,
		"phase":     "entry",
	}).Info("shim-rpc")
	return func(errp *error) {
		fields := logrus.Fields{
			"rpc":       method,
			"container": containerID,
			"phase":     "exit",
			"elapsed":   time.Since(start).String(),
		}
		if errp != nil && *errp != nil {
			fields["err"] = (*errp).Error()
		}
		shimLog.WithFields(fields).Info("shim-rpc")
	}
}

// New returns a new shim service that can be used via GRPC
func New(ctx context.Context, id string, publisher cdshim.Publisher, shutdown func()) (cdshim.Shim, error) {
	shimLog = shimLog.WithFields(logrus.Fields{
		"sandbox": id,
		"pid":     os.Getpid(),
	})
	// Discard the log before shim init its log output. Otherwise
	// it will output into stdio, from which containerd would like
	// to get the shim's socket address.
	logrus.SetOutput(io.Discard)
	opts := ctx.Value(cdshim.OptsKey{}).(cdshim.Opts)
	if !opts.Debug {
		logrus.SetLevel(logrus.WarnLevel)
	}
	vci.SetLogger(ctx, shimLog)
	katautils.SetLogger(ctx, shimLog, shimLog.Logger.Level)

	ns, found := namespaces.Namespace(ctx)
	if !found {
		return nil, fmt.Errorf("shim namespace cannot be empty")
	}

	s := &service{
		id:            id,
		pid:           uint32(os.Getpid()),
		ctx:           ctx,
		containers:    make(map[string]*container),
		events:        make(chan interface{}, chSize),
		ec:            make(chan exit, bufferSize),
		cancel:        shutdown,
		namespace:     ns,
		migrationMode: ModeOwner,
	}

	go s.processExits()

	forwarder := s.newEventsForwarder(ctx, publisher)
	go forwarder.forward()

	return s, nil
}

type exit struct {
	timestamp time.Time
	id        string
	execid    string
	pid       uint32
	status    int
}

// service is the shim implementation of a remote shim over GRPC
type service struct {
	sandbox vc.VCSandbox

	ctx      context.Context
	rootCtx  context.Context // root context for tracing
	rootSpan otelTrace.Span

	containers map[string]*container

	config *oci.RuntimeConfig

	monitor chan error
	ec      chan exit

	events chan interface{}

	cancel func()

	id string

	// Namespace from upper container engine
	namespace string

	// migrationMode reports the sandbox's live-migration lifecycle
	// state. The default zero value of an unset field would be the
	// empty string; New() initializes this explicitly to ModeOwner
	// so reads from un-initialized callers return a meaningful value.
	// State transitions and per-mode op gating are introduced in
	// follow-up changes; today this field is always ModeOwner.
	// See docs/design/live-migration-shim-lifecycle.md.
	//
	// Protected by migrationMu, which is INTENTIONALLY a separate
	// mutex from s.mu. Create() holds s.mu for the entire duration of
	// its inner goroutine; that goroutine drives BeginMigrateIncoming
	// → transitionMigrationMode and stores migrationServer, both of
	// which would deadlock on s.mu. Using a dedicated mutex keeps
	// migration-state mutations wait-free against the Create
	// critical section. Also covers migrationServer, since it is
	// set/cleared from the same code path.
	migrationMu   sync.Mutex
	migrationMode SandboxMigrationMode

	// migrationAbortReason records WHY the most recent transition to
	// ModeFailed happened when the cause was an abort (coordinator
	// AbortHandoff, source-inactivity watchdog) rather than a QEMU
	// error. QEMU-originated failures carry their own LastError via
	// query-migrate; abort-originated ones previously surfaced as
	// mode=failed with lastError=null — observable only via journal
	// archaeology. /migration/status reports this when the hypervisor
	// has no error of its own. Protected by migrationMu.
	migrationAbortReason string

	// migrationSocketPathOverride lets tests bind the destination
	// MigrationCoordinator server somewhere other than the
	// conventional /run/kata-containers/<id>/migrate.sock. Empty
	// means use the conventional path.
	migrationSocketPathOverride string

	// migrationServer is the destination-side MigrationCoordinator
	// gRPC server. Non-nil only between BeginMigrateIncoming and
	// stopMigrationServer. Protected by migrationMu (NOT s.mu —
	// see the comment on migrationMu above for the deadlock that
	// motivates a separate mutex).
	migrationServer interface {
		SocketPath() string
		Stop() error
	}

	// pendingMigrationState holds the JSON-serialized SandboxState
	// received from the source. The full swap into the live
	// sandbox struct lands in a follow-up; for now we validate the
	// payload and stash it for inspection.
	pendingMigrationState []byte

	// migrationSourceContainers maps OCI container-name to the
	// source's CRI container ID, populated by /migration/topology
	// on the destination. Used by Create() at workload-container
	// time so the dest's fresh Container struct can adopt the
	// source ID as InternalID — keeping agent RPCs ("exec",
	// "stop", "signal") routable across the migration boundary.
	// Protected by migrationMu.
	migrationSourceContainers map[string]string

	// migrationContinueCh gates the post-precopy cutover when the
	// pause-before-switchover capability is set on the outgoing
	// migration. BeginMigrateOut creates a fresh channel before
	// issuing the QMP `migrate` command and parks on it once QEMU
	// reaches the "pre-switchover" phase; /migration/continue's
	// handler closes the channel to release the wait, which lets
	// BeginMigrateOut issue `migrate-continue` and proceed through
	// the final cutover + CompleteHandoff.
	//
	// Lifecycle (always under migrationMu):
	//   nil               — no outgoing migration in pre-switchover
	//   non-nil, open     — paused at pre-switchover, awaiting continue
	//   non-nil, closed   — continue received; BeginMigrateOut owns
	//                       the cleanup back to nil
	migrationContinueCh chan struct{}

	mu          sync.Mutex
	eventSendMu sync.Mutex

	// hypervisor pid, Since this shimv2 cannot get the container processes pid from VM,
	// thus for the returned values needed pid, just return the hypervisor's
	// pid directly.
	hpid uint32

	// shim's pid
	pid uint32
}

func newCommand(ctx context.Context, id, containerdBinary, containerdAddress string) (*sysexec.Cmd, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	args := []string{
		"-namespace", ns,
		"-address", containerdAddress,
		"-publish-binary", containerdBinary,
		"-id", id,
	}
	opts := ctx.Value(cdshim.OptsKey{}).(cdshim.Opts)
	if opts.Debug {
		args = append(args, "-debug")
	}
	cmd := sysexec.Command(self, args...)
	cmd.Dir = cwd

	// Set the go max process to 2 in case the shim forks too much process
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	return cmd, nil
}

func setupMntNs() error {
	err := unix.Unshare(unix.CLONE_NEWNS)
	if err != nil {
		return err
	}

	err = unix.Mount("", "/", "", unix.MS_REC|unix.MS_SLAVE, "")
	if err != nil {
		err = fmt.Errorf("failed to mount with slave: %v", err)
		return err
	}

	err = unix.Mount("", "/", "", unix.MS_REC|unix.MS_SHARED, "")
	if err != nil {
		err = fmt.Errorf("failed to mount with shared: %v", err)
		return err
	}

	return nil
}

// StartShim is a binary call that starts a kata shimv2 service which will
// implement the ShimV2 APIs such as create/start/update etc containers.
func (s *service) StartShim(ctx context.Context, opts cdshim.StartOpts) (_ string, retErr error) {
	bundlePath, err := os.Getwd()
	if err != nil {
		return "", err
	}

	address, err := getAddress(ctx, bundlePath, opts.Address, opts.ID)
	if err != nil {
		return "", err
	}
	if address != "" {
		if err := cdshim.WriteAddress("address", address); err != nil {
			return "", err
		}
		return address, nil
	}

	cmd, err := newCommand(ctx, opts.ID, opts.ContainerdBinary, opts.Address)
	if err != nil {
		return "", err
	}

	address, err = cdshim.SocketAddress(ctx, opts.Address, opts.ID)
	if err != nil {
		return "", err
	}

	socket, err := cdshim.NewSocket(address)

	if err != nil {
		if !cdshim.SocketEaddrinuse(err) {
			return "", err
		}
		if err := cdshim.RemoveSocket(address); err != nil {
			return "", errors.Wrap(err, "remove already used socket")
		}
		if socket, err = cdshim.NewSocket(address); err != nil {
			return "", err
		}
	}

	defer func() {
		if retErr != nil {
			socket.Close()
			_ = cdshim.RemoveSocket(address)
		}
	}()

	f, err := socket.File()
	if err != nil {
		return "", err
	}

	cmd.ExtraFiles = append(cmd.ExtraFiles, f)

	goruntime.LockOSThread()
	if os.Getenv("SCHED_CORE") != "" {
		if err := utils.Create(utils.ProcessGroup); err != nil {
			return "", errors.Wrap(err, "enable sched core support")
		}
	}

	if err := setupMntNs(); err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}

	goruntime.UnlockOSThread()

	defer func() {
		if retErr != nil {
			cmd.Process.Kill()
		}
	}()

	if err = cdshim.WritePidFile("shim.pid", cmd.Process.Pid); err != nil {
		return "", err
	}
	if err = cdshim.WriteAddress("address", address); err != nil {
		return "", err
	}
	return address, nil
}

func (s *service) send(evt interface{}) {
	// for unit test, it will not initialize s.events
	if s.events != nil {
		s.events <- evt
	}
}

func (s *service) sendL(evt interface{}) {
	s.eventSendMu.Lock()
	if s.events != nil {
		s.events <- evt
	}
	s.eventSendMu.Unlock()
}

func getTopic(e interface{}) string {
	switch e.(type) {
	case *eventstypes.TaskCreate:
		return cdruntime.TaskCreateEventTopic
	case *eventstypes.TaskStart:
		return cdruntime.TaskStartEventTopic
	case *eventstypes.TaskOOM:
		return cdruntime.TaskOOMEventTopic
	case *eventstypes.TaskExit:
		return cdruntime.TaskExitEventTopic
	case *eventstypes.TaskDelete:
		return cdruntime.TaskDeleteEventTopic
	case *eventstypes.TaskExecAdded:
		return cdruntime.TaskExecAddedEventTopic
	case *eventstypes.TaskExecStarted:
		return cdruntime.TaskExecStartedEventTopic
	case *eventstypes.TaskPaused:
		return cdruntime.TaskPausedEventTopic
	case *eventstypes.TaskResumed:
		return cdruntime.TaskResumedEventTopic
	case *eventstypes.TaskCheckpointed:
		return cdruntime.TaskCheckpointedEventTopic
	default:
		shimLog.WithField("event-type", e).Warn("no topic for event type")
	}
	return cdruntime.TaskUnknownTopic
}

// Cleanup is a binary call that cleans up resources used by the shim
func (s *service) Cleanup(ctx context.Context) (_ *taskAPI.DeleteResponse, err error) {
	span, spanCtx := katatrace.Trace(s.rootCtx, shimLog, "Cleanup", shimTracingTags)
	defer span.End()

	//Since the binary cleanup will return the DeleteResponse from stdout to
	//containerd, thus we must make sure there is no any outputs in stdout except
	//the returned response, thus here redirect the log to stderr in case there's
	//any log output to stdout.
	logrus.SetOutput(os.Stderr)

	defer func() {
		err = toGRPC(err)
	}()

	if s.id == "" {
		return nil, errdefs.ToGRPCf(errdefs.ErrInvalidArgument, "the container id is empty, please specify the container id")
	}

	path, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	ociSpec, err := compatoci.ParseConfigJSON(path)
	if err != nil {
		return nil, err
	}

	containerType, err := oci.ContainerType(ociSpec)
	if err != nil {
		return nil, err
	}

	switch containerType {
	case vc.PodSandbox, vc.SingleContainer:
		err = cleanupContainer(spanCtx, s.id, s.id, path)
		if err != nil {
			return nil, err
		}
	case vc.PodContainer:
		sandboxID, err := oci.SandboxID(ociSpec)
		if err != nil {
			return nil, err
		}

		err = cleanupContainer(spanCtx, sandboxID, s.id, path)
		if err != nil {
			return nil, err
		}
	}

	return &taskAPI.DeleteResponse{
		ExitedAt:   timestamppb.New(time.Now()),
		ExitStatus: 128 + uint32(unix.SIGKILL),
	}, nil
}

// Create a new sandbox or container with the underlying OCI runtime
func (s *service) Create(ctx context.Context, r *taskAPI.CreateTaskRequest) (_ *taskAPI.CreateTaskResponse, err error) {
	defer shimRPCLog("Create", r.ID)(&err)
	shimLog.WithField("container", r.ID).Debug("Create() start")
	defer shimLog.WithField("container", r.ID).Debug("Create() end")
	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("create").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("create"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := katautils.VerifyContainerID(r.ID); err != nil {
		return nil, err
	}

	type Result struct {
		container *container
		err       error
	}
	ch := make(chan Result, 1)
	go func() {
		container, err := create(ctx, s, r)
		ch <- Result{container, err}
	}()

	select {
	case <-ctx.Done():
		return nil, errors.Errorf("create container timeout: %v", r.ID)
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		container := res.container
		container.status = task.Status_CREATED

		s.containers[r.ID] = container

		s.send(&eventstypes.TaskCreate{
			ContainerID: r.ID,
			Bundle:      r.Bundle,
			Rootfs:      r.Rootfs,
			IO: &eventstypes.TaskIO{
				Stdin:    r.Stdin,
				Stdout:   r.Stdout,
				Stderr:   r.Stderr,
				Terminal: r.Terminal,
			},
			Checkpoint: r.Checkpoint,
			Pid:        s.hpid,
		})

		return &taskAPI.CreateTaskResponse{
			Pid: s.hpid,
		}, nil
	}
}

// Start a process
func (s *service) Start(ctx context.Context, r *taskAPI.StartRequest) (_ *taskAPI.StartResponse, err error) {
	defer shimRPCLog("Start", r.ID)(&err)
	shimLog.WithField("container", r.ID).Debug("Start() start")
	defer shimLog.WithField("container", r.ID).Debug("Start() end")
	span, spanCtx := katatrace.Trace(s.rootCtx, shimLog, "Start", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("start").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	// Destination shim in Incoming mode: QEMU is up but paused on
	// "-S -incoming defer". The sandbox-pause container and the
	// workload container are coming via the migration handoff, so
	// the agent isn't reachable yet and there is nothing local for
	// us to start. Emit the TaskStart event so containerd advances
	// its task state to Running (which lets RunPodSandbox return
	// success), and return our hypervisor pid as the task pid like
	// the normal path. Real container lifecycle resumes when
	// onMigrationComplete fires and flips us back to Owner.
	if s.currentMigrationMode() == ModeIncoming && r.ExecID == "" {
		shimLog.WithField("container", r.ID).
			Warn("Start: incoming-migration mode; short-circuiting to emit TaskStart without agent call")
		s.eventSendMu.Lock()
		s.send(&eventstypes.TaskStart{
			ContainerID: r.ID,
			Pid:         s.hpid,
		})
		s.eventSendMu.Unlock()
		return &taskAPI.StartResponse{Pid: s.hpid}, nil
	}

	if err = s.checkOpAllowed("start"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}

	// hold the send lock so that the start events are sent before any exit events in the error case
	s.eventSendMu.Lock()
	defer s.eventSendMu.Unlock()

	//start a container
	if r.ExecID == "" {
		err = startContainer(spanCtx, s, c)
		if err != nil {
			return nil, errdefs.ToGRPC(err)
		}
		s.send(&eventstypes.TaskStart{
			ContainerID: c.id,
			Pid:         s.hpid,
		})
	} else {
		//start an exec
		_, err = startExec(spanCtx, s, r.ID, r.ExecID)
		if err != nil {
			return nil, errdefs.ToGRPC(err)
		}
		s.send(&eventstypes.TaskExecStarted{
			ContainerID: c.id,
			ExecID:      r.ExecID,
			Pid:         s.hpid,
		})
	}

	return &taskAPI.StartResponse{
		Pid: s.hpid,
	}, nil
}

// Delete the initial process and container
func (s *service) Delete(ctx context.Context, r *taskAPI.DeleteRequest) (_ *taskAPI.DeleteResponse, err error) {
	defer shimRPCLog("Delete", r.ID)(&err)
	shimLog.WithField("container", r.ID).Debug("Delete() start")
	defer shimLog.WithField("container", r.ID).Debug("Delete() end")
	span, spanCtx := katatrace.Trace(s.rootCtx, shimLog, "Delete", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("delete").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("delete"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}

	if r.ExecID == "" {
		if err = deleteContainer(spanCtx, s, c); err != nil {
			return nil, err
		}

		s.send(&eventstypes.TaskDelete{
			ContainerID: c.id,
			Pid:         s.hpid,
			ExitStatus:  c.exit,
			ExitedAt:    timestamppb.New(c.exitTime),
		})

		return &taskAPI.DeleteResponse{
			ExitStatus: c.exit,
			ExitedAt:   timestamppb.New(c.exitTime),
			Pid:        s.hpid,
		}, nil
	}
	//deal with the exec case
	execs, err := c.getExec(r.ExecID)
	if err != nil {
		return nil, err
	}

	c.deleteExec(r.ExecID)

	return &taskAPI.DeleteResponse{
		ExitStatus: uint32(execs.exitCode),
		ExitedAt:   timestamppb.New(execs.exitTime),
		Pid:        s.hpid,
	}, nil
}

// Exec an additional process inside the container
func (s *service) Exec(ctx context.Context, r *taskAPI.ExecProcessRequest) (_ *emptypb.Empty, err error) {
	defer shimRPCLog("Exec", r.ID)(&err)
	shimLog.WithField("container", r.ID).Debug("Exec() start")
	defer shimLog.WithField("container", r.ID).Debug("Exec() end")
	span, _ := katatrace.Trace(s.rootCtx, shimLog, "Exec", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		rpcDurationsHistogram.WithLabelValues("exec").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
		err = toGRPC(err)
	}()

	if err = s.checkOpAllowed("exec"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}

	if e, _ := c.getExec(r.ExecID); e != nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrAlreadyExists, "id %s", r.ExecID)
	}

	execs, err := newExec(c, r.Stdin, r.Stdout, r.Stderr, r.Terminal, r.Spec)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	c.setExec(r.ExecID, execs)

	s.send(&eventstypes.TaskExecAdded{
		ContainerID: c.id,
		ExecID:      r.ExecID,
	})

	return empty, nil
}

// ResizePty of a process
func (s *service) ResizePty(ctx context.Context, r *taskAPI.ResizePtyRequest) (_ *emptypb.Empty, err error) {
	shimLog.WithField("container", r.ID).Debug("ResizePty() start")
	defer shimLog.WithField("container", r.ID).Debug("ResizePty() end")
	span, spanCtx := katatrace.Trace(s.rootCtx, shimLog, "ResizePty", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("resize_pty").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("resize_pty"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}

	processID := c.id
	if r.ExecID != "" {
		execs, err := c.getExec(r.ExecID)
		if err != nil {
			return nil, err
		}
		execs.tty.height = r.Height
		execs.tty.width = r.Width

		processID = execs.id

	}
	err = s.sandbox.WinsizeProcess(spanCtx, c.id, processID, r.Height, r.Width)
	if err != nil {
		return nil, err
	}

	return empty, err
}

// State returns runtime state information for a process
func (s *service) State(ctx context.Context, r *taskAPI.StateRequest) (_ *taskAPI.StateResponse, err error) {
	defer shimRPCLog("State", r.ID)(&err)
	shimLog.WithField("container", r.ID).Debug("State() start")
	defer shimLog.WithField("container", r.ID).Debug("State() end")
	span, _ := katatrace.Trace(s.rootCtx, shimLog, "State", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("state").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("state"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}

	if r.ExecID == "" {
		// While migrating out, lie to containerd about the
		// container status: report Running regardless of the
		// underlying state so containerd does not reap the source
		// shim mid-handoff. See
		// docs/design/live-migration-shim-lifecycle.md "Containerd
		// reaps source shim too aggressively". migrationMode lives
		// on its own mutex (migrationMu) so reading it through
		// currentMigrationMode() is safe while holding s.mu.
		reportedStatus := c.status
		if s.currentMigrationMode() == ModeMigratingOut {
			reportedStatus = task.Status_RUNNING
		}
		return &taskAPI.StateResponse{
			ID:         c.id,
			Bundle:     c.bundle,
			Pid:        s.hpid,
			Status:     reportedStatus,
			Stdin:      c.stdin,
			Stdout:     c.stdout,
			Stderr:     c.stderr,
			Terminal:   c.terminal,
			ExitStatus: c.exit,
			ExitedAt:   timestamppb.New(c.exitTime),
		}, nil
	}

	//deal with exec case
	execs, err := c.getExec(r.ExecID)
	if err != nil {
		return nil, err
	}

	return &taskAPI.StateResponse{
		ID:         execs.id,
		Bundle:     c.bundle,
		Pid:        s.hpid,
		Status:     execs.status,
		Stdin:      execs.tty.stdin,
		Stdout:     execs.tty.stdout,
		Stderr:     execs.tty.stderr,
		Terminal:   execs.tty.terminal,
		ExitStatus: uint32(execs.exitCode),
		ExitedAt:   timestamppb.New(execs.exitTime),
	}, nil
}

// Pause the container
func (s *service) Pause(ctx context.Context, r *taskAPI.PauseRequest) (_ *emptypb.Empty, err error) {
	shimLog.WithField("container", r.ID).Debug("Pause() start")
	defer shimLog.WithField("container", r.ID).Debug("Pause() end")
	span, spanCtx := katatrace.Trace(s.rootCtx, shimLog, "Pause", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("pause").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("pause"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}

	c.status = task.Status_PAUSING

	err = s.sandbox.PauseContainer(spanCtx, r.ID)
	if err == nil {
		c.status = task.Status_PAUSED
		s.send(&eventstypes.TaskPaused{
			ContainerID: c.id,
		})
		return empty, nil
	}

	if status, err := s.getContainerStatus(c.id); err != nil {
		c.status = task.Status_UNKNOWN
	} else {
		c.status = status
	}

	return empty, err
}

// Resume the container
func (s *service) Resume(ctx context.Context, r *taskAPI.ResumeRequest) (_ *emptypb.Empty, err error) {
	shimLog.WithField("container", r.ID).Debug("Resume() start")
	defer shimLog.WithField("container", r.ID).Debug("Resume() end")
	span, spanCtx := katatrace.Trace(s.rootCtx, shimLog, "Resume", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("resume").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("resume"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}

	err = s.sandbox.ResumeContainer(spanCtx, c.id)
	if err == nil {
		c.status = task.Status_RUNNING
		s.send(&eventstypes.TaskResumed{
			ContainerID: c.id,
		})
		return empty, nil
	}

	if status, err := s.getContainerStatus(c.id); err != nil {
		c.status = task.Status_UNKNOWN
	} else {
		c.status = status
	}

	return empty, err
}

// Kill a process with the provided signal
// markContainerStoppedForTeardown transitions c to STOPPED and fires its exit
// channel so a no-op teardown kill (the in-guest process is unreachable and
// effectively gone) is observed by the kubelet as a terminated container.
// Without it, State/Wait keep reporting the container RUNNING after the no-op
// return, so the kubelet loops StopContainer and never advances to
// RemovePodSandbox — wedging the pod Terminating forever with a live shim
// (observed on a failed-incoming dest whose handoff never completed). The pod
// delete that follows still reaps the VM via stopVM. Caller holds s.mu and has
// already returned early when the container was STOPPED, so the buffered
// (size-1) exitCh is empty; the send is non-blocking regardless as a backstop.
// markContainerStoppedForTeardown flips c to STOPPED so the kubelet stops
// looping StopContainer (#268). publishExit additionally emits the TaskExit
// that containerd's StopContainer actually reaps on — and that is only safe on
// the CONFIRMED post-handoff path (ModeSaved/ModeMigrated), where the workload
// has genuinely departed.
//
// Why publishExit must be gated (#275 regression): the EVENT, not c.exitCh,
// is what unblocks containerd's StopContainer (s.ec -> processExits ->
// checkProcesses -> sendL). A normally-created container's process monitor
// feeds s.ec when its guest process exits; a migrated/adopted container (wired
// via startIOForMigratedContainers) has no such monitor, so the post-handoff
// source needs this explicit publish to self-reap instead of wedging
// Terminating. But the agent-unreachable Kill branch can fire MID-MIGRATION
// against a LIVE source (agent transiently unreachable during migrate-out);
// publishing a TaskExit there reaps the source while the hop is in flight,
// restarting it (observed: exitCode255 on a live source). So that branch passes
// publishExit=false — it still clears the kubelet wedge, but never reaps.
//
// The event is otherwise harmless: checkProcesses only emits TaskExit; it does
// not clean up /run/vc/vm or virtiofsd, so it never disturbs a destination that
// shares the migrated identity. The c.status guard makes it fire at most once.
func markContainerStoppedForTeardown(c *container, publishExit bool) {
	if c.status == task.Status_STOPPED {
		return
	}
	c.status = task.Status_STOPPED
	c.exit = exitCode255
	c.exitTime = time.Now()
	select {
	case c.exitCh <- exitCode255:
	default:
	}
	if publishExit && c.s != nil {
		go cReap(c.s, exitCode255, c.id, "", c.exitTime)
	}
}

func (s *service) Kill(ctx context.Context, r *taskAPI.KillRequest) (_ *emptypb.Empty, err error) {
	defer shimRPCLog("Kill", r.ID)(&err)
	shimLog.WithField("container", r.ID).Debug("Kill() start")
	defer shimLog.WithField("container", r.ID).Debug("Kill() end")
	span, spanCtx := katatrace.Trace(s.rootCtx, shimLog, "Kill", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("kill").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("kill"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	signum := syscall.Signal(r.Signal)

	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}

	processStatus := c.status
	processID := c.id
	if r.ExecID != "" {
		execs, err := c.getExec(r.ExecID)
		if err != nil {
			return nil, err
		}
		processID = execs.id
		if processID == "" {
			shimLog.WithFields(logrus.Fields{
				"sandbox":   s.sandbox.ID(),
				"container": c.id,
				"exec-id":   r.ExecID,
			}).Debug("Id of exec process to be signalled is empty")
			return empty, errors.New("The exec process does not exist")
		}
		processStatus = execs.status
	} else {
		r.All = true
	}

	// According to CRI specs, kubelet will call StopPodSandbox()
	// at least once before calling RemovePodSandbox, and this call
	// is idempotent, and must not return an error if all relevant
	// resources have already been reclaimed. And in that call it will
	// send a SIGKILL signal first to try to stop the container, thus
	// once the container has terminated, here should ignore this signal
	// and return directly.
	if (signum == syscall.SIGKILL || signum == syscall.SIGTERM) && processStatus == task.Status_STOPPED {
		shimLog.WithFields(logrus.Fields{
			"sandbox":   s.sandbox.ID(),
			"container": c.id,
			"exec-id":   r.ExecID,
		}).Debug("process has already stopped")
		return empty, nil
	}

	// A saved (snapshot) or migrated sandbox has no live local VM to signal:
	// ModeSaved pauses the guest before checkpointing, ModeMigrated handed
	// it off to a destination. A teardown SIGKILL/SIGTERM would otherwise
	// bounce off SignalProcess with errSandboxNotRunning and surface to the
	// kubelet as a FailedKillPod warning on every suspend/migration. Treat it
	// as already-stopped — the same idempotency CRI expects for a terminated
	// container (the pod delete that follows reclaims the bundle regardless).
	if signum == syscall.SIGKILL || signum == syscall.SIGTERM {
		if mode := s.currentMigrationMode(); mode == ModeSaved || mode == ModeMigrated {
			shimLog.WithFields(logrus.Fields{
				"sandbox":   s.sandbox.ID(),
				"container": c.id,
				"mode":      mode.String(),
			}).Debug("sandbox saved/migrated; local VM not running — treating kill as a no-op")
			// #268: like the agent-unreachable branch below, a bare no-op leaves
			// the container RUNNING, so the kubelet loops StopContainer and never
			// reaches RemovePodSandbox — a successful migration SOURCE (ModeMigrated;
			// QEMU already handed off) then hangs Terminating with a live shim.
			// Mark it STOPPED so the kubelet observes termination and finalizes the
			// pod; here the shim stays alive to serve State/Wait/Delete, so the
			// teardown completes cleanly. Container-level kill only (ExecID=="").
			// publishExit=true: confirmed post-handoff (ModeSaved/ModeMigrated),
			// so the adopted source needs the explicit TaskExit to self-reap.
			if r.ExecID == "" {
				markContainerStoppedForTeardown(c, true)
			}
			return empty, nil
		}
		// FR-054 / #254: a teardown SIGKILL/SIGTERM whose in-guest agent is
		// unreachable would block forever in SignalProcess, failing
		// StopPodSandbox and wedging the pod Terminating with a live QEMU. This
		// bites a warm-resumed (dual-identity) pod, or a source whose agent has
		// moved before the mode reflects it. The signal can't reach the guest
		// anyway, so treat it as already-stopped — the pod delete that follows
		// reaps the VM via stopVM's SIGKILL. Keyed on actual reachability (a
		// short bounded Check), so a healthy container kill is unaffected.
		if s.sandbox != nil && !s.sandbox.AgentReachable(spanCtx) {
			shimLog.WithFields(logrus.Fields{
				"sandbox":   s.sandbox.ID(),
				"container": c.id,
			}).Warn("teardown kill: in-guest agent unreachable — treating kill as a no-op so the pod can terminate (FR-054)")
			// #268: a bare no-op return leaves the container RUNNING, so the
			// kubelet loops StopContainer and never reaches RemovePodSandbox —
			// the pod (and its shim) hangs Terminating forever (failed-incoming
			// dest whose handoff never completed). Mark it STOPPED so the kubelet
			// observes termination and advances to delete. Container-level kill
			// only (ExecID==""); an exec is gone with the unreachable guest.
			// publishExit=false (#275): this branch can fire mid-migrate-out
			// against a LIVE source (agent transiently unreachable); a published
			// TaskExit would reap and restart it. Marking STOPPED clears the
			// kubelet wedge without reaping. A failed-incoming dest that needs
			// reaping is force-deleted by the controller's failed-dest recovery.
			if r.ExecID == "" {
				markContainerStoppedForTeardown(c, false)
			}
			return empty, nil
		}
	}

	return empty, s.sandbox.SignalProcess(spanCtx, c.id, processID, signum, r.All)
}

// Pids returns all pids inside the container
// Since for kata, it cannot get the process's pid from VM,
// thus only return the hypervisor's pid directly.
func (s *service) Pids(ctx context.Context, r *taskAPI.PidsRequest) (_ *taskAPI.PidsResponse, err error) {
	shimLog.WithField("container", r.ID).Debug("Pids() start")
	defer shimLog.WithField("container", r.ID).Debug("Pids() end")
	span, _ := katatrace.Trace(s.rootCtx, shimLog, "Pids", shimTracingTags)
	defer span.End()

	var processes []*task.ProcessInfo

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("pids").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("pids"); err != nil {
		return nil, err
	}

	pInfo := task.ProcessInfo{
		Pid: s.hpid,
	}
	processes = append(processes, &pInfo)

	return &taskAPI.PidsResponse{
		Processes: processes,
	}, nil
}

// CloseIO of a process
func (s *service) CloseIO(ctx context.Context, r *taskAPI.CloseIORequest) (_ *emptypb.Empty, err error) {
	shimLog.WithField("container", r.ID).Debug("CloseIO() start")
	defer shimLog.WithField("container", r.ID).Debug("CloseIO() end")
	span, _ := katatrace.Trace(s.rootCtx, shimLog, "CloseIO", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("close_io").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("close_io"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}

	stdin := c.stdinPipe
	stdinCloser := c.stdinCloser

	if r.ExecID != "" {
		execs, err := c.getExec(r.ExecID)
		if err != nil {
			return nil, err
		}
		stdin = execs.stdinPipe
		stdinCloser = execs.stdinCloser
	}

	// wait until the stdin io copy terminated, otherwise
	// some contents would not be forwarded to the process.
	<-stdinCloser
	if err := stdin.Close(); err != nil {
		return nil, errors.Wrap(err, "close stdin")
	}

	return empty, nil
}

// Checkpoint the container
func (s *service) Checkpoint(ctx context.Context, r *taskAPI.CheckpointTaskRequest) (_ *emptypb.Empty, err error) {
	shimLog.WithField("container", r.ID).Debug("Checkpoint() start")
	defer shimLog.WithField("container", r.ID).Debug("Checkpoint() end")
	span, _ := katatrace.Trace(s.rootCtx, shimLog, "Checkpoint", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("checkpoint").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	return nil, errdefs.ToGRPCf(errdefs.ErrNotImplemented, "service Checkpoint")
}

// Connect returns shim information such as the shim's pid
func (s *service) Connect(ctx context.Context, r *taskAPI.ConnectRequest) (_ *taskAPI.ConnectResponse, err error) {
	defer shimRPCLog("Connect", r.ID)(&err)
	shimLog.WithField("container", r.ID).Debug("Connect() start")
	defer shimLog.WithField("container", r.ID).Debug("Connect() end")
	span, _ := katatrace.Trace(s.rootCtx, shimLog, "Connect", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("connect").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("connect"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return &taskAPI.ConnectResponse{
		ShimPid: s.pid,
		//Since kata cannot get the container's pid in VM, thus only return the hypervisor's pid.
		TaskPid: s.hpid,
	}, nil
}

func (s *service) Shutdown(ctx context.Context, r *taskAPI.ShutdownRequest) (_ *emptypb.Empty, err error) {
	defer shimRPCLog("Shutdown", r.ID)(&err)
	// Why so loud here: an unexpected Shutdown() (especially one with
	// len(s.containers)==0 hitting os.Exit) is the most likely cause
	// of post-migration ttrpc closure. Dump enough info to attribute
	// the call: which container was passed, who called (containerd
	// usually), and what s.containers looked like.
	s.mu.Lock()
	containerIDs := make([]string, 0, len(s.containers))
	for cid := range s.containers {
		containerIDs = append(containerIDs, cid)
	}
	s.mu.Unlock()
	shimLog.WithFields(logrus.Fields{
		"container":        r.ID,
		"now":              r.Now,
		"containersInShim": containerIDs,
		"hpid":             s.hpid,
	}).Warn("Shutdown(): RPC entry")
	shimLog.WithField("container", r.ID).Debug("Shutdown() start")
	defer shimLog.WithField("container", r.ID).Debug("Shutdown() end")
	span, _ := katatrace.Trace(s.rootCtx, shimLog, "Shutdown", shimTracingTags)

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("shutdown").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("shutdown"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	if len(s.containers) != 0 {
		s.mu.Unlock()

		span.End()
		s.rootSpan.End()
		katatrace.StopTracing(s.rootCtx)

		return empty, nil
	}
	s.mu.Unlock()

	span.End()
	katatrace.StopTracing(s.rootCtx)

	s.cancel()

	// Since we only send an shutdown qmp command to qemu when do stopSandbox, and
	// didn't wait until qemu process's exit, thus we'd better to make sure it had
	// exited when shimv2 terminated. Thus here to do the last cleanup of the hypervisor.
	syscall.Kill(int(s.hpid), syscall.SIGKILL)

	// os.Exit() will terminate program immediately, the defer functions won't be executed,
	// so we add defer functions again before os.Exit().
	// Refer to https://pkg.go.dev/os#Exit
	shimLog.WithField("container", r.ID).Debug("Shutdown() end")
	rpcDurationsHistogram.WithLabelValues("shutdown").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))

	// Goroutine stack dump just before os.Exit. When the shim exits
	// unexpectedly (which manifests downstream as "ttrpc: closed" on
	// the next containerd RPC), this lets post-mortem attribute the
	// exit to a specific code path.
	stackBuf := make([]byte, 32*1024)
	stackLen := goruntime.Stack(stackBuf, true /* all goroutines */)
	shimLog.WithFields(logrus.Fields{
		"container": r.ID,
		"hpid":      s.hpid,
		"stack":     string(stackBuf[:stackLen]),
	}).Warn("Shutdown(): os.Exit(0) imminent")

	os.Exit(0)

	// This will never be called, but this is only there to make sure the
	// program can compile.
	return empty, nil
}

func (s *service) Stats(ctx context.Context, r *taskAPI.StatsRequest) (_ *taskAPI.StatsResponse, err error) {
	shimLog.WithField("container", r.ID).Debug("Stats() start")
	defer shimLog.WithField("container", r.ID).Debug("Stats() end")
	span, spanCtx := katatrace.Trace(s.rootCtx, shimLog, "Stats", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("stats").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("stats"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}

	// A saved or migrated sandbox has no live local VM. marshalMetrics would
	// issue a StatsContainer RPC over a vsock to a guest that is gone (paused
	// for ModeSaved, handed off for ModeMigrated) and block forever — while
	// holding s.mu, which also serializes Kill. That wedges the source pod
	// Terminating because the kubelet's StopContainer can never acquire the
	// lock. Answer with empty metrics instead of touching the departed guest.
	if mode := s.currentMigrationMode(); mode == ModeSaved || mode == ModeMigrated {
		data, err := marshalEmptyMetrics()
		if err != nil {
			return nil, err
		}
		return &taskAPI.StatsResponse{Stats: data}, nil
	}

	data, err := marshalMetrics(spanCtx, s, c.id)
	if err != nil {
		return nil, err
	}

	return &taskAPI.StatsResponse{
		Stats: data,
	}, nil
}

// Update a running container
func (s *service) Update(ctx context.Context, r *taskAPI.UpdateTaskRequest) (_ *emptypb.Empty, err error) {
	shimLog.WithField("container", r.ID).Debug("Update() start")
	defer shimLog.WithField("container", r.ID).Debug("Update() end")
	span, spanCtx := katatrace.Trace(s.rootCtx, shimLog, "Update", shimTracingTags)
	defer span.End()

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("update").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("update"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var resources *specs.LinuxResources
	v, err := typeurl.UnmarshalAny(r.Resources)
	if err != nil {
		return nil, err
	}
	resources, ok := v.(*specs.LinuxResources)
	if !ok {
		return nil, errdefs.ToGRPCf(errdefs.ErrInvalidArgument, "Invalid resources type for %s", s.id)
	}

	err = s.sandbox.UpdateContainer(spanCtx, r.ID, *resources)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return empty, nil
}

// Wait for a process to exit
func (s *service) Wait(ctx context.Context, r *taskAPI.WaitRequest) (_ *taskAPI.WaitResponse, err error) {
	shimLog.WithField("container", r.ID).Debug("Wait() start")
	defer shimLog.WithField("container", r.ID).Debug("Wait() end")
	span, _ := katatrace.Trace(s.rootCtx, shimLog, "Wait", shimTracingTags)
	defer span.End()

	var ret uint32

	start := time.Now()
	defer func() {
		err = toGRPC(err)
		rpcDurationsHistogram.WithLabelValues("wait").Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()

	if err = s.checkOpAllowed("wait"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	c, err := s.getContainer(r.ID)
	s.mu.Unlock()

	if err != nil {
		return nil, err
	}

	//wait for container
	if r.ExecID == "" {
		ret = <-c.exitCh

		// refill the exitCh with the container process's exit code in case
		// there were other waits on this process.
		c.exitCh <- ret
	} else { //wait for exec
		execs, err := c.getExec(r.ExecID)
		if err != nil {
			return nil, err
		}
		ret = <-execs.exitCh

		// refill the exitCh with the exec process's exit code in case
		// there were other waits on this process.
		execs.exitCh <- ret
	}

	return &taskAPI.WaitResponse{
		ExitStatus: ret,
		ExitedAt:   timestamppb.New(c.exitTime),
	}, nil
}

func (s *service) processExits() {
	for e := range s.ec {
		s.checkProcesses(e)
	}
}

func (s *service) checkProcesses(e exit) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := e.execid
	if id == "" {
		id = e.id
	}

	s.sendL(&eventstypes.TaskExit{
		ContainerID: e.id,
		ID:          id,
		Pid:         e.pid,
		ExitStatus:  uint32(e.status),
		ExitedAt:    timestamppb.New(e.timestamp),
	})
}

func (s *service) getContainer(id string) (*container, error) {
	c := s.containers[id]

	if c == nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrNotFound, "container does not exist %s", id)
	}

	return c, nil
}

func (s *service) getContainerStatus(containerID string) (task.Status, error) {
	cStatus, err := s.sandbox.StatusContainer(containerID)
	if err != nil {
		return task.Status_UNKNOWN, err
	}

	var status task.Status
	switch cStatus.State.State {
	case types.StateReady:
		status = task.Status_CREATED
	case types.StateRunning:
		status = task.Status_RUNNING
	case types.StatePaused:
		status = task.Status_PAUSED
	case types.StateStopped:
		status = task.Status_STOPPED
	}

	return status, nil
}
