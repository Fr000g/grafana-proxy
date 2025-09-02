# 构建阶段
FROM golang:alpine AS builder

WORKDIR /app
COPY . .

RUN apk add --no-cache git && \
    go build -ldflags "-X main.version=$(git describe --tags 2>/dev/null || git rev-parse --short HEAD 2>/dev/null || echo dev)" -o grafana-proxy

# 运行阶段
FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/grafana-proxy .

EXPOSE 3000

ENTRYPOINT ["./grafana-proxy"]
CMD ["--listen", "0.0.0.0:3000"]
