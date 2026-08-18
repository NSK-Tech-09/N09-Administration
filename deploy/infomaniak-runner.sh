#!/usr/bin/env bash
set -Eeuo pipefail

root=${N09_DEPLOY_ROOT:-$(pwd -P)}
shared="$root/shared"
trigger="$shared/restart.trigger"
ack="$shared/restart.ack"

[[ -f "$shared/.env" ]] || { echo "missing $shared/.env" >&2; exit 1; }
[[ -f "$shared/start-command" ]] || { echo "missing $shared/start-command" >&2; exit 1; }
touch "$trigger"

child=
stop_child() {
  [[ -n ${child:-} ]] || return 0
  kill -TERM "$child" 2>/dev/null || true
  for _ in {1..20}; do
    kill -0 "$child" 2>/dev/null || return 0
    sleep 1
  done
  kill -KILL "$child" 2>/dev/null || true
}
trap 'stop_child; exit 0' TERM INT

while true; do
  generation=$(cat "$trigger")
  release=$(readlink -f "$root/current")
  [[ -d "$release" ]] || { echo "current release is missing" >&2; exit 1; }

  set -a
  # shellcheck disable=SC1091
  . "$shared/.env"
  [[ ! -f "$release/release.env" ]] || . "$release/release.env"
  set +a
  start_command=$(cat "$shared/start-command")

  cd "$root"
  bash -lc "exec $start_command" &
  child=$!
  printf '%s\t%s\n' "$generation" "$release" >"$ack.next"
  mv -f "$ack.next" "$ack"

  while kill -0 "$child" 2>/dev/null; do
    [[ $(cat "$trigger") == "$generation" ]] || { stop_child; break; }
    sleep 1
  done
  wait "$child" || true
  child=
  sleep 1
done
