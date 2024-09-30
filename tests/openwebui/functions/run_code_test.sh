#!/usr/bin/env bash

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

docker run --rm \
    --security-opt=seccomp=unconfined \
    --security-opt=apparmor=unconfined \
    --security-opt=label=type:container_engine_t \
    --mount=type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup,readonly=false \
    --mount=type=bind,source=/proc,target=/proc2,readonly=false,bind-recursive=disabled \
    --mount=type=bind,source="$REPO_DIR",target=/test \
    ghcr.io/open-webui/open-webui:main \
    python3 /test/open-webui/functions/run_code.py --self_test
