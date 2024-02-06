FROM golang:1.21 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY backend.go ./
RUN go build backend.go


FROM debian:12-slim
RUN --mount=type=cache,target=/var/cache/apt \
    apt update && \
    apt install -y --no-install-recommends \
      pdns-server \
      pdns-backend-pipe && \
    rm -rf /var/lib/apt/lists/*
# Always use /app/target as the command
COPY --from=builder /app/backend /app/backend
COPY run.sh /app/run.sh
EXPOSE 53 53/udp
EXPOSE 53 53/tcp
CMD /app/run.sh
