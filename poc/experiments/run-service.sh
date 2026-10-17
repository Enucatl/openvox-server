#!/bin/sh
set -eu
umask 077
lab=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
suite=${1:-service}
case "$suite" in service|enrollment) ;; *) echo 'Expected service or enrollment' >&2; exit 2 ;; esac
context=$(mktemp -d "$lab/experiments/service-context.XXXXXX")
result=$(mktemp -d "$lab/experiments/service-result.XXXXXX")
image="openvox-mldsa-service:$(basename "$context" | tr '[:upper:]' '[:lower:]')"
container="openvox-mldsa-$(basename "$context")"
cleanup() {
  code=$?
  trap - EXIT HUP INT TERM
  if docker container inspect "$container" >/dev/null 2>&1; then
    docker cp "$container:/test/." "$result/" || true
    docker rm -f "$container" >/dev/null || true
  fi
  docker image rm "$image" >/dev/null 2>&1 || true
  rm -rf "$context"
  printf 'Private evidence: %s\n' "$result"
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
cp "$lab"/experiments/"$suite"/* "$context/"
cp "$lab"/experiments/tls/generate.sh "$lab"/experiments/tls/rogue.sh "$lab"/experiments/tls/crls.sh "$context/"
cp "$lab/openvox-server/resources/ext/java.security.mldsa" "$context/"
if [ "$suite" = enrollment ]; then
  cp "$lab/experiments/source-build/output/puppet-server-release.jar" "$context/server.jar"
  cp "$lab/experiments/service/StartupProbe.java" "$context/"
  cp -R "$lab/openvox/lib" "$context/agent-lib"
  cp "$lab/openvox-server/src/clj/puppetlabs/puppetserver/certificate_authority.clj" "$context/certificate_authority.clj"
  cp "$lab/openvox-server/ezbake/config/conf.d/auth.conf" "$context/auth.conf"
  cp "$lab/experiments/vault/setup.sh" "$context/vault-setup.sh"
  cp "$lab/experiments/vault/vault-poc.rb" "$context/"
  cp -R "$lab/vault-hiera/lib" "$context/hiera-lib"
  cp -R "$lab/openvoxserver-ca/lib" "$context/ca-lib"
  git -C "$lab/openvox" rev-parse HEAD > "$result/agent-base.txt"
  git -C "$lab/openvox" diff > "$result/agent.patch"
  git -C "$lab/jvm-ssl-utils" rev-parse HEAD > "$result/ssl-utils-base.txt"
  git -C "$lab/jvm-ssl-utils" diff > "$result/ssl-utils.patch"
  git -C "$lab/vault-hiera" rev-parse HEAD > "$result/vault-hiera-base.txt"
  git -C "$lab/vault-hiera" diff > "$result/vault-hiera.patch"
  git -C "$lab/openvoxserver-ca" rev-parse HEAD > "$result/openvoxserver-ca-base.txt"
  git -C "$lab/openvoxserver-ca" diff > "$result/openvoxserver-ca.patch"
fi
git -C "$lab/openvox-server" rev-parse HEAD > "$result/source-base.txt"
git -C "$lab/openvox-server" diff > "$result/source.patch"
timeout 1800 docker build --tag "$image" "$context"
docker image inspect "$image" --format '{{.Id}}' > "$result/image-id.txt"
docker create --name "$container" --network none --cap-drop ALL \
  --security-opt no-new-privileges --memory 2g --cpus 2 \
  --entrypoint /bin/sh "$image" /test/run.sh
timeout 900 docker start -a "$container" || true
if [ "$(docker inspect --format '{{.State.Running}}' "$container")" != false ]; then
  echo 'Service test exceeded its deadline or attach failed while still running' >&2
  exit 124
fi
code=$(docker inspect --format '{{.State.ExitCode}}' "$container")
docker inspect --format '{{json .State}}' "$container" > "$result/container-state.json"
exit "$code"
