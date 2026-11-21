#!/usr/bin/env bash
set -euo pipefail
umask 077

helper='alpine@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f'
volumes=(vector-anchor-outbox vector-anchor-state trace-audit-outbox mcp-shield-outbox)

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

[[ $# == 3 ]] || fail "Usage: $0 backup|restore COMPOSE_PROJECT BACKUP_DIRECTORY"
operation=$1
project=$2
directory=$3
[[ $project =~ ^[a-z0-9][a-z0-9_-]*$ ]] || fail 'Invalid Compose project name.'
archives=()
for key in "${volumes[@]}"; do archives+=("$key.tar"); done

case "$operation" in
  backup)
    sources=()
    for key in "${volumes[@]}"; do
      volume=$(docker volume ls --quiet \
        --filter "label=com.docker.compose.project=$project" \
        --filter "label=com.docker.compose.volume=$key")
      [[ -n $volume && $volume != *$'\n'* ]] || fail "Expected one volume for $project/$key."
      running=$(docker ps --quiet --filter "volume=$volume")
      [[ -z $running ]] || fail "Stop containers using $volume before backing it up."
      sources+=("$volume")
    done
    mkdir -m 700 -- "$directory"
    for index in "${!sources[@]}"; do
      docker run --rm --network none --read-only \
        --mount "type=volume,src=${sources[$index]},dst=/data,readonly" \
        "$helper" tar -cpf - -C /data . > "$directory/${archives[$index]}"
    done
    (cd -- "$directory" && sha256sum "${archives[@]}" > SHA256SUMS)
    ;;
  restore)
    (cd -- "$directory" && sha256sum "${archives[@]}" | cmp -s SHA256SUMS -) \
      || fail 'The backup is incomplete or failed checksum verification.'
    for key in "${volumes[@]}"; do
      existing=$(docker volume ls --quiet \
        --filter "label=com.docker.compose.project=$project" \
        --filter "label=com.docker.compose.volume=$key")
      if [[ -n $existing ]] || docker volume inspect "${project}_$key" >/dev/null 2>&1; then
        fail "Restore requires a new project with no existing volume for $key."
      fi
    done
    # Docker may return an existing volume on a concurrent create. Only write
    # to volumes bearing this invocation's label, and only clean up those.
    owner_label='io.blackmonolith.restore-id'
    restore_id=$(python3 -c 'import uuid; print(uuid.uuid4())')
    cleanup_failed_restore() {
      local status=$? owned
      if (( status != 0 )); then
        if owned=$(docker volume ls --quiet --filter "label=$owner_label=$restore_id"); then
          while IFS= read -r volume; do
            [[ -z $volume ]] || docker volume rm "$volume" >/dev/null || \
              printf 'Could not remove partial restore volume %s\n' "$volume" >&2
          done <<< "$owned"
        else
          printf 'Could not list partial restore volumes for %s\n' "$restore_id" >&2
        fi
      fi
    }
    trap cleanup_failed_restore EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    for key in "${volumes[@]}"; do
      volume="${project}_$key"
      docker volume create --label "com.docker.compose.project=$project" \
        --label "com.docker.compose.volume=$key" --label "$owner_label=$restore_id" "$volume" >/dev/null
      owner=$(docker volume inspect --format "{{ index .Labels \"$owner_label\" }}" "$volume")
      [[ $owner == "$restore_id" ]] || fail "Another operation owns $volume."
      docker run --rm --interactive --network none --read-only \
        --mount "type=volume,src=$volume,dst=/data" "$helper" \
        sh -ec 'test -z "$(ls -A /data)"; tar -xpf - -C /data' < "$directory/$key.tar"
    done
    ;;
  *) fail 'Operation must be backup or restore.' ;;
esac

printf '%s\n' "Module volume $operation complete for $project."
