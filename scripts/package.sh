#!/bin/sh
set -eu
version=${1:?version required}
arch=${2:?architecture required}
case "$arch" in amd64|arm64) ;; *) exit 2;; esac
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$stage/recense" ./cmd/recense
scripts/fetch-scanner.sh syft 1.55.0 linux "$arch" "$stage"
scripts/fetch-scanner.sh grype 0.121.0 linux "$arch" "$stage"
cp deploy/systemd/recense.service deploy/systemd/recense.logrotate "$stage/"
cp README.md LICENSE THIRD_PARTY.md "$stage/"
mkdir -p dist
tar -czf "dist/recense_linux_${arch}.tar.gz" -C "$stage" .
