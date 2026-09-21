#!/usr/bin/env bash
set -euo pipefail

export APPIMAGE_EXTRACT_AND_RUN=1
source /root/.cargo/env

npm ci
npx tauri build --bundles appimage,deb --config '{"bundle":{"createUpdaterArtifacts":false}}'
