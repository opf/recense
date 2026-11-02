#!/bin/sh
# Download an exact upstream release and verify the archive before extraction.
set -eu
name=$1
version=$2
os=$3
arch=$4
dest=$5
case "$name" in syft|grype) ;; *) exit 2;; esac
case "$os/$arch" in linux/amd64|linux/arm64|darwin/arm64|darwin/amd64) ;; *) exit 2;; esac
mkdir -p "$dest"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
archive="${name}_${version}_${os}_${arch}.tar.gz"
base="https://github.com/anchore/$name/releases/download/v$version"
curl --fail --location --retry 3 --silent --show-error "$base/$archive" -o "$tmp/$archive"
curl --fail --location --retry 3 --silent --show-error "$base/${name}_${version}_checksums.txt" -o "$tmp/checksums.txt"
(cd "$tmp" && awk -v file="$archive" '$2 == file {print}' checksums.txt > selected.sha256 && test -s selected.sha256 && shasum -a 256 -c selected.sha256)
tar -xzf "$tmp/$archive" -C "$dest" "$name"
tar -xOf "$tmp/$archive" LICENSE > "$dest/LICENSE.$name"
chmod 755 "$dest/$name"
