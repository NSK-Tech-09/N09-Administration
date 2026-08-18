#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "$0")/.." && pwd -P)
shared="$root/shared"
nonce="$(date -u +%Y%m%dT%H%M%SZ)-$$"
printf '%s\n' "$nonce" >"$shared/restart.trigger.next"
mv -f "$shared/restart.trigger.next" "$shared/restart.trigger"

for _ in {1..30}; do
  [[ -f "$shared/restart.ack" ]] && read -r acknowledged _ <"$shared/restart.ack" || acknowledged=
  [[ "$acknowledged" == "$nonce" ]] && exit 0
  sleep 1
done
echo "restart acknowledgement timed out" >&2
exit 1
