#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/elk/.env"
COMPOSE_FILE="$ROOT/elk/docker-compose.yml"
COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")
ARGS=()

if [ ! -f "$ENV_FILE" ]; then
  cp "$ROOT/elk/.env.example" "$ENV_FILE"
fi

if [ "${1:-}" = "--reset" ]; then
  ARGS=(-v)
fi

"${COMPOSE[@]}" down "${ARGS[@]}"

if [ "${1:-}" = "--reset" ]; then
  echo "ELK stack stopped and volumes removed."
else
  echo "ELK stack stopped. Run with --reset to remove Elasticsearch and Logstash volumes."
fi
