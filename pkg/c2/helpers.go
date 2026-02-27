package c2

import (
	"context"
	"time"
)

// contextBackground returns a context with a 10-second timeout for DNS lookups.
func contextBackground() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}
