FROM golang:1.24-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=0.1.0
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o akmcp ./cmd

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/akmcp /usr/local/bin/akmcp
ENTRYPOINT ["akmcp"]
