FROM golang:1.27.4-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY schema ./schema
COPY secrets ./secrets
COPY runtime ./runtime
ARG VERSION
ARG COMMIT
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/livepeer/control-center/runtime/httpsource.Version=${VERSION} -X github.com/livepeer/control-center/runtime/httpsource.Commit=${COMMIT}" -o /livepeer-runtime ./runtime/cmd/livepeer-runtime

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /livepeer-runtime /usr/local/bin/livepeer-runtime
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/livepeer-runtime"]
