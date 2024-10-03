#!/usr/bin/env bash

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

echo 'Running tool self-tests...' >&2
docker run --rm \
    --security-opt=seccomp=unconfined \
    --security-opt=apparmor=unconfined \
    --security-opt=label=type:container_engine_t \
    --mount=type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup,readonly=false \
    --mount=type=bind,source=/proc,target=/proc2,readonly=false,bind-recursive=disabled \
    --mount=type=bind,source="$REPO_DIR",target=/test \
    ghcr.io/open-webui/open-webui:main \
    python3 /test/open-webui/tools/run_code.py --self_test "$@"

echo 'Checking cgroupfs presence enforcement enabled (this should fail)...' >&2
docker run --rm \
    --security-opt=seccomp=unconfined \
    --security-opt=apparmor=unconfined \
    --security-opt=label=type:container_engine_t \
    --mount=type=tmpfs,target=/sys/fs/cgroup,readonly=true \
    --mount=type=bind,source=/proc,target=/proc2,readonly=false,bind-recursive=disabled \
    --mount=type=bind,source="$REPO_DIR",target=/test \
    --env=CODE_EVAL_VALVE_OVERRIDE_MAX_RAM_MEGABYTES=32 \
    --env=CODE_EVAL_VALVE_OVERRIDE_REQUIRE_RESOURCE_LIMITING=true \
    ghcr.io/open-webui/open-webui:main \
    python3 /test/open-webui/tools/run_code.py \
        --use_sample_code --want_status=SANDBOX_ERROR "$@"

echo 'Checking cgroupfs presence enforcement disabled (this should succeed)...' >&2
docker run --rm \
    --security-opt=seccomp=unconfined \
    --security-opt=apparmor=unconfined \
    --security-opt=label=type:container_engine_t \
    --mount=type=tmpfs,target=/sys/fs/cgroup,readonly=true \
    --mount=type=bind,source=/proc,target=/proc2,readonly=false,bind-recursive=disabled \
    --mount=type=bind,source="$REPO_DIR",target=/test \
    --env=CODE_EVAL_VALVE_OVERRIDE_MAX_RAM_MEGABYTES=32 \
    --env=CODE_EVAL_VALVE_OVERRIDE_REQUIRE_RESOURCE_LIMITING=false \
    ghcr.io/open-webui/open-webui:main \
    python3 /test/open-webui/tools/run_code.py \
        --use_sample_code --want_status=OK "$@"
