FROM golang:1.21-alpine AS builder

WORKDIR /go/src/github.com/ryanbekhen/nanoproxy

ARG OWNER=ryanbekhen
ARG PROJECT=nanoproxy

ARG VERSION=0.0.0
ARG COMMIT=unknown

COPY . .

RUN go mod tidy \
    && CGO_ENABLED=0 GOOS=linux go build -o nanoproxy -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT}" proxy.go

FROM busybox:1.36.1-glibc

WORKDIR /root
COPY --from=builder /go/src/github.com/ryanbekhen/nanoproxy/nanoproxy /usr/local/bin/nanoproxy

ENTRYPOINT ["nanoproxy"]