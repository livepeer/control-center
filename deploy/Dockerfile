# syntax=docker/dockerfile:1
FROM golang:1.27.4-bookworm AS api-build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY api/cmd ./api/cmd
COPY api/internal ./api/internal
COPY schema ./schema
COPY secrets ./secrets
COPY runtime ./runtime
ARG COMMIT=unknown
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/livepeer/control-center/api/internal/controlplane.buildRevision=${COMMIT}" -o /controlcenter ./api/cmd/controlcenter

FROM alpine:3.24 AS api
ARG COMMIT=unknown
LABEL org.opencontainers.image.revision=${COMMIT}
RUN apk add --no-cache ca-certificates
COPY --from=api-build /controlcenter /usr/local/bin/controlcenter
USER 65532:65532
ENTRYPOINT ["controlcenter"]
CMD ["serve", "--config", "/etc/controlcenter/config.toml"]

FROM node:26-alpine AS ui-build
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY ui/ ./
RUN npm run build

FROM caddy:2-alpine AS web
COPY --from=ui-build /src/ui/dist /srv
COPY deploy/Caddyfile /etc/caddy/Caddyfile
ENV XDG_CONFIG_HOME=/tmp/config XDG_DATA_HOME=/tmp/data
USER 65532:65532
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
