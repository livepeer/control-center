FROM golang:1.27.3-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY schema ./schema
COPY runtime ./runtime
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /livepeer-runtime ./runtime/cmd/livepeer-runtime

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /livepeer-runtime /usr/local/bin/livepeer-runtime
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/livepeer-runtime"]
