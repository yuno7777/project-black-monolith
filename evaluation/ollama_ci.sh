#!/usr/bin/env bash
set -euo pipefail

pid_file="${RUNNER_TEMP:?}/monolith-ollama.pid"
log_file="$RUNNER_TEMP/monolith-ollama.log"

start_ollama() {
  ollama serve >> "$log_file" 2>&1 &
  local pid=$!
  printf '%s\n' "$pid" > "$pid_file"
  for _ in {1..60}; do
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    if curl --max-time 2 -fs http://127.0.0.1:11434/api/tags >/dev/null; then return; fi
    sleep 1
  done
  tail -60 "$log_file" >&2
  return 1
}

restart_ollama() {
  local pid
  read -r pid < "$pid_file"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  kill "$pid" 2>/dev/null || true
  for _ in {1..15}; do
    if ! kill -0 "$pid" 2>/dev/null || [[ $(ps -p "$pid" -o stat=) == Z* ]]; then
      start_ollama
      return
    fi
    sleep 1
  done
  echo "Ollama did not stop after SIGTERM" >&2
  tail -60 "$log_file" >&2
  return 1
}

case "$1" in
  start) start_ollama ;;
  evaluate)
    model=$2
    report=$3
    command=(python evaluation/real_models.py trace --model "$model"
      --external evaluation/results/external.json --output "$report")
    if "${command[@]}"; then
      exit 0
    else
      status=$?
    fi
    if [[ $status != 75 ]]; then exit "$status"; fi
    printf 'Restarting Ollama and retrying %s after the inference timeout.\n' "$model" >&2
    restart_ollama
    "${command[@]}"
    ;;
  *)
    echo "Usage: $0 start | evaluate MODEL REPORT" >&2
    exit 2
    ;;
esac
