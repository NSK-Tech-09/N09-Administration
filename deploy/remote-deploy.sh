#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

die() { printf '%s\n' "deployment error: $*" >&2; exit 1; }

[[ $# -eq 6 ]] || die "expected: root archive sha256 commit health-url retention"
root=$1 archive=$2 expected_sha=$3 commit=$4 health_url=$5 retention=$6
[[ $root == /* && $root != / ]] || die "deployment root must be an absolute non-root path"
[[ $archive == "$root/incoming/"* ]] || die "archive must be inside incoming"
[[ $commit =~ ^[0-9a-f]{40}$ ]] || die "invalid commit"
[[ $expected_sha =~ ^[0-9a-f]{64}$ ]] || die "invalid checksum"
[[ $retention =~ ^[2-9][0-9]*$ ]] || die "retention must be at least 2"

mkdir -p "$root/incoming" "$root/releases" "$root/shared"
[[ -f "$root/shared/.env" ]] || die "missing protected shared/.env"
[[ -x "$root/shared/restart.sh" ]] || die "missing protected shared/restart.sh"
actual_sha=$(sha256sum "$archive" | cut -d ' ' -f 1)
[[ $actual_sha == "$expected_sha" ]] || die "archive checksum mismatch"

release="$root/releases/$commit"
previous=$(readlink -f "$root/current" 2>/dev/null || true)
cleanup() { rm -f -- "$archive" "$root/incoming/remote-deploy.sh" "$root/current.next"; }
trap cleanup EXIT
if [[ -e $release ]]; then
  [[ -f "$release/.artifact-sha256" && $(cat "$release/.artifact-sha256") == "$expected_sha" ]] || die "existing immutable release differs"
else
  mkdir "$release"
  tar -xzf "$archive" -C "$release" --no-same-owner --no-same-permissions
  printf '%s\n' "$expected_sha" > "$release/.artifact-sha256"
fi
[[ -f "$release/release.env" && -f "$release/service-node/server.mjs" ]] || die "incomplete release"
if find "$release" -name '.env' -o -name '.env.production' | grep -q .; then die "secret-like environment file in release"; fi
chmod -R a-w "$release"

ln -s "$release" "$root/current.next"
mv -Tf "$root/current.next" "$root/current"
if ! "$root/shared/restart.sh"; then
  [[ -n $previous ]] && ln -sfn "$previous" "$root/current"
  "$root/shared/restart.sh" || true
  die "restart failed; previous release restored"
fi

healthy=false
for _ in 1 2 3 4 5 6; do
  if body=$(curl --fail --silent --show-error --connect-timeout 10 --max-time 20 "$health_url") &&
     HEALTH_BODY="$body" EXPECTED_COMMIT="$commit" node -e 'const b=JSON.parse(process.env.HEALTH_BODY); process.exit(b.status === "ok" && (b.release?.commit === process.env.EXPECTED_COMMIT) ? 0 : 1)'; then
    healthy=true; break
  fi
  sleep 5
done
if [[ $healthy != true ]]; then
  [[ -n $previous ]] || die "health failed and no previous release exists"
  ln -sfn "$previous" "$root/current"
  "$root/shared/restart.sh" || true
  die "health failed; previous release restored"
fi

mapfile -t old < <(find "$root/releases" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | tail -n "+$((retention + 1))" | cut -d ' ' -f 2-)
for candidate in "${old[@]}"; do
  [[ $(readlink -f "$root/current") == "$candidate" || $previous == "$candidate" ]] || rm -rf -- "$candidate"
done
printf 'deployed %s\n' "$commit"
