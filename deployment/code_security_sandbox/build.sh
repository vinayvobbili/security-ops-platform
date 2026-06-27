#!/usr/bin/env bash
# Build the code-security sandbox image. Dev and prod share this host's docker
# daemon, so building once tags it for both worktrees' web apps. Re-run after
# changing the Dockerfile or toolrunner.py.
set -euo pipefail
cd "$(dirname "$0")"
IMAGE="${CODE_SEC_SANDBOX_IMAGE:-ir-code-sec-sandbox:current}"
echo "Building ${IMAGE} ..."
docker build -t "${IMAGE}" .
echo "Done. Image: ${IMAGE}"
docker images "${IMAGE}" --format '  {{.Repository}}:{{.Tag}}  {{.Size}}  (built {{.CreatedSince}})'
