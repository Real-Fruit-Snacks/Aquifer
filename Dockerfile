# Multi-stage build for Aquifer implant
# Produces a minimal scratch container with just the static binary

# ---- Build stage ----
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache make git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build

# ---- Release stage ----
FROM scratch

COPY --from=builder /src/build/implant /aquifer

ENTRYPOINT ["/aquifer"]
