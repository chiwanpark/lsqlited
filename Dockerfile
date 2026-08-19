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
 && install -d -o lsqlited -g lsqlited -m 0750 /var/lib/lsqlited /etc/lsqlited \
 && install -d -o root -g root -m 0755 /docker-entrypoint-initdb.d

COPY --from=build /out/lsqlited /usr/local/bin/lsqlited
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

USER lsqlited:lsqlited
WORKDIR /var/lib/lsqlited
EXPOSE 7890
# The entry point seeds the databases from /docker-entrypoint-initdb.d and then
# execs the daemon, so the flags below are still the daemon's own.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["-config", "/etc/lsqlited/config.yaml"]
