#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
build() {
  local goos="$1" goarch="$2" suffix="$3"
  echo "Building ${goos}/${goarch}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="-s -w" -o "dist/browsersec-${suffix}" ./cmd/browsersec
}
build linux amd64 linux-amd64
build linux arm64 linux-arm64
build windows amd64 windows-amd64.exe
build darwin amd64 macos-amd64
build darwin arm64 macos-arm64
sha256sum dist/* > dist/SHA256SUMS.txt
