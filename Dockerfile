# syntax=docker/dockerfile:1
ARG GO_VERSION=1.24
ARG DEBIAN_VERSION=bookworm

FROM golang:${GO_VERSION}-${DEBIAN_VERSION} AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG VERSION=

ENV CGO_ENABLED=1
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath \
      -ldflags="-s -w -X github.com/chiwanpark/lsqlited/internal/version.version=${VERSION}" \
      -o /out/lsqlited ./cmd/lsqlited


FROM debian:${DEBIAN_VERSION}-slim

RUN groupadd --system --gid 10001 lsqlited \
 && useradd --system --uid 10001 --gid 10001 \
      --home-dir /var/lib/lsqlited --shell /usr/sbin/nologin lsqlited \
 && install -d -o lsqlited -g lsqlited -m 0750 /var/lib/lsqlited /etc/lsqlited

COPY --from=build /out/lsqlited /usr/local/bin/lsqlited

USER lsqlited:lsqlited
WORKDIR /var/lib/lsqlited
EXPOSE 7890
ENTRYPOINT ["/usr/local/bin/lsqlited"]
CMD ["-config", "/etc/lsqlited/config.yaml"]
