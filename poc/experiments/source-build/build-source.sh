#!/bin/sh
set -eu
umask 077
checks=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
lab=$(CDPATH= cd -- "$checks/../.." && pwd)
result=$(mktemp -d "$checks/output-reproduction.XXXXXX")
run_id="$(date +%s)-$$"
image="openvox-mldsa-source-build:$run_id"
container="openvox-mldsa-source-build-$run_id"
created=no
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ "$created" = yes ]; then
    docker inspect --format '{{.State.ExitCode}}' "$container" > "$result/container-exit.txt" || :
    docker cp "$container:/output/." "$result/" || { [ "$status" -ne 0 ] || status=1; }
    docker rm -f "$container" >/dev/null 2>&1 || :
  fi
  docker image inspect --format '{{.Id}}' "$image" > "$result/image-id.txt" 2>/dev/null || :
  docker image rm "$image" >/dev/null 2>&1 || :
  printf 'Source build evidence: %s\n' "$result"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
timeout 1800 docker build --tag "$image" "$checks" > "$result/builder.log" 2>&1
docker create --name "$container" --memory 2g --cpus 2 --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=bind,source=$lab/openvox-server,target=/source,readonly" \
  --mount "type=bind,source=$lab/jvm-ssl-utils,target=/ssl-input,readonly" \
  --mount "type=bind,source=$checks,target=/checks,readonly" \
  --entrypoint /bin/sh "$image" /checks/run.sh > "$result/container-id.txt"
created=yes
timeout 1800 docker start -a "$container" > "$result/container.log" 2>&1
status=$(docker inspect --format '{{.State.ExitCode}}' "$container")
[ "$status" -eq 0 ] || exit "$status"
