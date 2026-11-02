FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm AS build
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/recense ./cmd/recense
COPY scripts/fetch-scanner.sh /fetch-scanner.sh
RUN sh /fetch-scanner.sh syft 1.56.0 linux "$TARGETARCH" /out && sh /fetch-scanner.sh grype 0.121.0 linux "$TARGETARCH" /out

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /usr/local/bin/
ENV HOME=/var/lib/recense XDG_CACHE_HOME=/var/lib/recense/cache
COPY LICENSE THIRD_PARTY.md /usr/share/doc/recense/
LABEL org.opencontainers.image.licenses="MIT"
WORKDIR /var/lib/recense
ENTRYPOINT ["/usr/local/bin/recense"]
