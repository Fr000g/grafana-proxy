# Build stage
FROM golang:1.24.5-alpine AS builder

WORKDIR /go/src/github.com/Luzifer/grafana-proxy

# Install build dependencies
RUN set -ex \
    && apk update && apk upgrade \
    && apk add --update git

# Copy source code and build
COPY . .
RUN set -ex \
    && go mod tidy \
    && go install -ldflags "-X main.version=$(git describe --tags || git rev-parse --short HEAD || echo dev)"

# Runtime stage - minimal alpine image
FROM alpine:3.22.0

# Install required runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy only the binary from builder stage
COPY --from=builder /go/bin/grafana-proxy /usr/local/bin/

EXPOSE 3001

ENTRYPOINT ["/usr/local/bin/grafana-proxy"]
CMD ["--listen", "0.0.0.0:3001"]
