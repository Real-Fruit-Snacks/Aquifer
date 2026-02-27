// Package version provides build-time version information injected via ldflags.
//
//	go build -ldflags "-X github.com/Real-Fruit-Snacks/Aquifer/pkg/version.Version=1.0.0 \
//	  -X github.com/Real-Fruit-Snacks/Aquifer/pkg/version.Commit=$(git rev-parse --short HEAD) \
//	  -X github.com/Real-Fruit-Snacks/Aquifer/pkg/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
package version

// These variables are set at build time via -ldflags -X.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// String returns a human-readable version string.
func String() string {
	return Version + " (" + Commit + ") built " + BuildDate
}
