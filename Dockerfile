FROM --platform=$BUILDPLATFORM golang:1.27@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /out/webterm ./cmd/webterm \
 && mkdir /out/data

# guacd (the Apache Guacamole proxy that does the RDP) is published for amd64 and arm64.
# It runs as uid 1000, and WebTerm starts it, so one container does everything.
FROM guacamole/guacd:1.6.0@sha256:8974eaa9ba32f713daf311e7cc8cd7e4cdfba1edea39eed75524e78ef4b08f4f
COPY --from=build /out/webterm /webterm
COPY --from=build --chown=1000:1000 /out/data /data
ENV WEBTERM_PORT=3000
EXPOSE 3000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["/webterm", "-healthcheck"]
ENTRYPOINT ["/webterm"]
