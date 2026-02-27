"""Polymorphic beacon path/method constants matching Go's polymorphic_beacon.go."""

from __future__ import annotations

# All 18 beacon paths from beaconPaths in polymorphic_beacon.go
BEACON_PATHS: list[str] = [
    "/api/v1/health",
    "/api/v2/status",
    "/api/v1/metrics",
    "/api/v1/config",
    "/api/v2/events",
    "/api/v1/telemetry",
    "/v1/check",
    "/v2/heartbeat",
    "/api/reports",
    "/api/v1/logs",
    "/oauth/token",
    "/api/v1/updates",
    "/graphql",
    "/api/v2/sync",
    "/api/v1/notifications",
    "/.well-known/openid-configuration",
    "/api/v1/analytics",
    "/cdn-cgi/trace",
]

# Methods from selectMethod() in polymorphic_beacon.go
BEACON_METHODS: list[str] = ["POST", "PUT", "PATCH"]

# Registration path (not polymorphic — fixed endpoint for key exchange)
REGISTRATION_PATH: str = "/api/v1/register"

# Default beacon path from config (not polymorphic, but always accepted)
DEFAULT_BEACON_PATH: str = "/api/v1/beacon"

