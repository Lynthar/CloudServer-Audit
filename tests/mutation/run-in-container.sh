#!/usr/bin/env bash
# Run tests/mutation/run.sh inside a throwaway systemd container built from the
# Dockerfile next to this script. Arguments are passed through (case filter).
# Needs Docker; --privileged because systemd must be PID 1 with a writable cgroup.
set -euo pipefail

MUTATION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${MUTATION_DIR}/../.." && pwd)"
IMAGE="vpssec-mutation-host"

docker build -q -t "$IMAGE" -f "${MUTATION_DIR}/Dockerfile" "${MUTATION_DIR}" >/dev/null

# A copy, not a bind mount: the run writes state/, reports/, backups/ and
# logs/ under the tree, and rollback restores into the container's /etc.
cid=$(docker run -d --rm --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw "$IMAGE")
trap 'docker stop -t 2 "$cid" >/dev/null' EXIT

for _ in $(seq 1 30); do
    state=$(docker exec "$cid" systemctl is-system-running 2>/dev/null || true)
    [[ "$state" == "running" || "$state" == "degraded" ]] && break
    sleep 1
done

docker cp "${PROJECT_ROOT}/." "$cid:/opt/vpssec"
docker exec "$cid" bash /opt/vpssec/tests/mutation/run.sh "$@"
