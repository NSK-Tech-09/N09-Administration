#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

die() { printf '%s\n' "deployment error: $*" >&2; exit 1; }
validate_root() { [[ $1 == /* && $1 != / ]] || die "deployment root must be an absolute non-root path"; }
read_state() {
  [[ -f $state ]] || die "missing deployment state"
  mapfile -t transaction <"$state"
  [[ ${transaction[0]:-} == "$commit" ]] || die "deployment state belongs to another commit"
  previous=${transaction[1]:-}
  archive=${transaction[2]:-}
  phase=${transaction[3]:-}
}
cleanup_transaction() {
  find "$root/incoming" -mindepth 1 -maxdepth 1 -type f -delete
  rm -f -- "$state"
  rm -rf -- "$lock"
}

[[ $# -ge 3 ]] || die "expected: action root commit [arguments]"
action=$1 root=$2 commit=$3
validate_root "$root"
[[ $commit =~ ^[0-9a-f]{40}$ ]] || die "invalid commit"
state="$root/shared/deployment.state"
lock="$root/shared/deployment.lock"

case "$action" in
  prepare)
    [[ $# -eq 7 ]] || die "prepare expects: root commit archive sha256 retention health-url"
    archive=$4 expected_sha=$5 retention=$6 health_url=$7
    [[ $archive == "$root/incoming/"* ]] || die "archive must be inside incoming"
    [[ $expected_sha =~ ^[0-9a-f]{64}$ ]] || die "invalid checksum"
    [[ $retention =~ ^[2-9][0-9]*$ ]] || die "retention must be at least 2"
    mkdir -p "$root/incoming" "$root/releases" "$root/shared"
    if [[ -f $state ]]; then
      mapfile -t interrupted <"$state"
      interrupted_commit=${interrupted[0]:-}
      [[ $interrupted_commit =~ ^[0-9a-f]{40}$ ]] || die "invalid stale deployment state"
      [[ $(readlink -f "$root/current") == "$root/releases/$interrupted_commit" ]] || die "unfinished unhealthy deployment requires rollback"
      if [[ ${interrupted[3]:-} != healthy ]]; then
        body=$(curl --fail --silent --show-error --connect-timeout 10 --max-time 20 "$health_url") || die "cannot verify interrupted deployment"
        HEALTH_BODY="$body" EXPECTED_COMMIT="$interrupted_commit" node -e 'const b=JSON.parse(process.env.HEALTH_BODY); process.exit(b.status === "ok" && b.release?.commit === process.env.EXPECTED_COMMIT ? 0 : 1)' || die "unfinished unhealthy deployment requires rollback"
      fi
      rm -f -- "$state"
      rm -rf -- "$lock"
    fi
    mkdir "$lock" || die "another deployment transaction is active"
    trap 'rm -rf -- "$lock"' ERR
    [[ ! -e $state ]] || die "stale deployment state exists"
    [[ -f "$root/shared/.env" ]] || die "missing protected shared/.env"
    [[ -x "$root/shared/restart.sh" ]] || die "missing protected shared/restart.sh"
    install -m 700 "$0" "$root/shared/deploy-transaction.sh"
    actual_sha=$(sha256sum "$archive" | cut -d ' ' -f 1)
    [[ $actual_sha == "$expected_sha" ]] || die "archive checksum mismatch"
    release="$root/releases/$commit"
    previous=$(readlink -f "$root/current" 2>/dev/null || true)
    if [[ -e $release ]]; then
      [[ -f "$release/.artifact-sha256" && $(cat "$release/.artifact-sha256") == "$expected_sha" ]] || die "existing immutable release differs"
    else
      mkdir "$release"
      tar -xzf "$archive" -C "$release" --no-same-owner --no-same-permissions
      printf '%s\n' "$expected_sha" >"$release/.artifact-sha256"
    fi
    [[ -f "$release/release.env" && -f "$release/service-node/server.mjs" ]] || die "incomplete release"
    if find "$release" -name '.env' -o -name '.env.production' | grep -q .; then die "secret-like environment file in release"; fi
    chmod -R a-w "$release"
    printf '%s\n%s\n%s\n%s\n' "$commit" "$previous" "$archive" prepared >"$state.next"
    mv -f "$state.next" "$state"
    ln -s "$release" "$root/current.next"
    mv -Tf "$root/current.next" "$root/current"
    trap - ERR
    ;;
  confirm)
    [[ $# -eq 3 ]] || die "confirm expects: root commit"
    read_state
    [[ $(readlink -f "$root/current") == "$root/releases/$commit" ]] || die "current release does not match transaction"
    printf '%s\n%s\n%s\n%s\n' "$commit" "$previous" "$archive" healthy >"$state.next"
    mv -f "$state.next" "$state"
    ;;
  finalize)
    [[ $# -eq 4 ]] || die "finalize expects: root commit retention"
    retention=$4
    [[ $retention =~ ^[2-9][0-9]*$ ]] || die "retention must be at least 2"
    if [[ ! -f $state ]]; then
      [[ $(readlink -f "$root/current") == "$root/releases/$commit" ]] || die "missing deployment state"
      printf 'already deployed %s\n' "$commit"
      exit 0
    fi
    read_state
    [[ $phase == healthy ]] || die "release health was not confirmed"
    [[ $(readlink -f "$root/current") == "$root/releases/$commit" ]] || die "current release does not match transaction"
    current=$(readlink -f "$root/current")
    keep=("$current")
    [[ $previous != "$current" && $previous == "$root/releases/"* ]] && keep+=("$previous")
    mapfile -t ordered < <(find "$root/releases" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | cut -d ' ' -f 2-)
    for candidate in "${ordered[@]}"; do
      kept=false
      for protected in "${keep[@]}"; do [[ $candidate == "$protected" ]] && kept=true; done
      [[ $kept == true || ${#keep[@]} -ge $retention ]] || keep+=("$candidate")
    done
    for candidate in "${ordered[@]}"; do
      kept=false
      for protected in "${keep[@]}"; do [[ $candidate == "$protected" ]] && kept=true; done
      if [[ $kept != true ]]; then
        chmod -R u+w -- "$candidate"
        rm -rf -- "$candidate"
      fi
    done
    cleanup_transaction
    printf 'deployed %s\n' "$commit"
    ;;
  rollback)
    [[ $# -eq 3 ]] || die "rollback expects: root commit"
    if [[ ! -f $state ]]; then
      [[ $(readlink -f "$root/current") != "$root/releases/$commit" ]] || die "missing deployment state"
      exit 0
    fi
    read_state
    [[ -n $previous && -d $previous ]] || die "previous release is unavailable"
    ln -sfn "$previous" "$root/current"
    cleanup_transaction
    ;;
  *) die "unknown action" ;;
esac
