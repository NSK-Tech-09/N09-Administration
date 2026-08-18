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
}
cleanup_transaction() {
  rm -f -- "$archive" "$root/incoming/remote-deploy.sh" "$state"
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
    [[ $# -eq 6 ]] || die "prepare expects: root commit archive sha256 retention"
    archive=$4 expected_sha=$5 retention=$6
    [[ $archive == "$root/incoming/"* ]] || die "archive must be inside incoming"
    [[ $expected_sha =~ ^[0-9a-f]{64}$ ]] || die "invalid checksum"
    [[ $retention =~ ^[2-9][0-9]*$ ]] || die "retention must be at least 2"
    mkdir -p "$root/incoming" "$root/releases" "$root/shared"
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
    printf '%s\n%s\n%s\n' "$commit" "$previous" "$archive" >"$state.next"
    mv -f "$state.next" "$state"
    ln -s "$release" "$root/current.next"
    mv -Tf "$root/current.next" "$root/current"
    trap - ERR
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
    [[ $(readlink -f "$root/current") == "$root/releases/$commit" ]] || die "current release does not match transaction"
    mapfile -t old < <(find "$root/releases" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | tail -n "+$((retention + 1))" | cut -d ' ' -f 2-)
    cleanup_transaction
    for candidate in "${old[@]}"; do
      [[ $(readlink -f "$root/current") == "$candidate" || $previous == "$candidate" ]] || rm -rf -- "$candidate"
    done
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
