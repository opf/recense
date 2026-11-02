#!/bin/sh
# Usage: sudo sh install.sh [v0.1.0]
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run this installer as root.' >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo 'Recense installs on Linux hosts.' >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'systemd is required.' >&2; exit 1; }
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Unsupported architecture' >&2; exit 1;; esac
version=${1:-latest}
case "$version" in latest) base=https://github.com/opf/recense/releases/latest/download;; v[0-9]*) base="https://github.com/opf/recense/releases/download/$version";; *) echo 'Expected a release tag, such as v0.1.0' >&2; exit 1;; esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
archive="recense_linux_${arch}.tar.gz"
curl --fail --location --retry 3 --silent --show-error "$base/$archive" -o "$tmp/$archive"
curl --fail --location --retry 3 --silent --show-error "$base/checksums.txt" -o "$tmp/checksums.txt"
(cd "$tmp" && awk -v file="$archive" '$2 == file {print}' checksums.txt > selected.sha256 && test -s selected.sha256 && sha256sum -c selected.sha256)
mkdir "$tmp/unpack"
tar -xzf "$tmp/$archive" -C "$tmp/unpack"
# Stop only after the download and verification have succeeded.
systemctl stop recense.service 2>/dev/null || true
install -d -m 755 /opt/recense/bin /etc/recense
install -d -m 750 /var/lib/recense /var/log/recense
for binary in recense syft grype; do install -m 755 "$tmp/unpack/$binary" "/opt/recense/bin/$binary"; done
install -m 644 "$tmp/unpack/LICENSE.syft" "$tmp/unpack/LICENSE.grype" "$tmp/unpack/LICENSE" "$tmp/unpack/THIRD_PARTY.md" /opt/recense/
install -m 644 "$tmp/unpack/recense.service" /etc/systemd/system/recense.service
if [ -d /etc/logrotate.d ]; then install -m 644 "$tmp/unpack/recense.logrotate" /etc/logrotate.d/recense; fi
if [ ! -f /etc/recense/environment ]; then
 printf '%s\n' '# RECENSE_ENVIRONMENT=production' '# RECENSE_CLUSTER=eks-production' > /etc/recense/environment
 chmod 600 /etc/recense/environment
fi
systemctl daemon-reload
systemctl enable --now recense.service
printf '%s\n' 'Recense installed. Logs: /var/log/recense/events.jsonl' 'Status: systemctl status recense' 'Configure your existing OpenTelemetry collector using deploy/otel/filelog.yaml.'
