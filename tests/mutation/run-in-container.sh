#!/usr/bin/env bash
# Run tests/mutation/run.sh inside a throwaway systemd container built from the
# Dockerfile next to this script. Arguments are passed through (case filter).
# Always --strict: the cases are written for this image, so a skip here means
# it drifted. Needs Docker; --privileged because systemd must be PID 1.
set -euo pipefail

MUTATION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${MUTATION_DIR}/../.." && pwd)"
IMAGE="vpssec-mutation-host"

docker build -q -t "$IMAGE" -f "${MUTATION_DIR}/Dockerfile" "${MUTATION_DIR}" >/dev/null

# A kernel case plants the sysctl named in its _PARAM. Outside net.* no container
# has its own copy: under --privileged the write lands on the Docker host's kernel.
host_keys=$(sed -n '/^_PARAM="net\./d; s/^_PARAM="\([^"]*\)"$/\1/p' "${MUTATION_DIR}"/cases/*.case | sort -u)
host_saved=""

# The host's values go back after the container is gone, so that no case still
# running inside it (an interrupted run) can set them again afterwards.
cleanup() {
    local line args=()
    docker stop -t 2 "$cid" >/dev/null || true
    [[ -n "$host_saved" ]] || return 0
    while IFS= read -r line; do args+=("${line%% = *}=${line#* = }"); done <<<"$host_saved"
    docker run --rm --privileged --entrypoint sysctl "$IMAGE" -q -w "${args[@]}" >/dev/null \
        || printf 'Docker host sysctls not put back; they were:\n%s\n' "$host_saved" >&2
}

# A copy, not a bind mount: the run writes state/, reports/, backups/ and
# logs/ under the tree, and rollback restores into the container's /etc.
cid=$(docker run -d --rm --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw "$IMAGE")
trap cleanup EXIT
# shellcheck disable=SC2086 # one key per word
[[ -z "$host_keys" ]] || host_saved=$(docker exec "$cid" sysctl -e $host_keys)

for _ in $(seq 1 30); do
    state=$(docker exec "$cid" systemctl is-system-running 2>/dev/null || true)
    [[ "$state" == "running" || "$state" == "degraded" ]] && break
    sleep 1
done

docker cp "${PROJECT_ROOT}/." "$cid:/opt/vpssec"
docker exec "$cid" bash /opt/vpssec/tests/mutation/run.sh --strict "$@"
