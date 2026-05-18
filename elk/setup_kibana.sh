#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/elk/.env"
COMPOSE_FILE="$ROOT/elk/docker-compose.yml"
COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")

if [ ! -f "$ENV_FILE" ]; then
  cp "$ROOT/elk/.env.example" "$ENV_FILE"
fi

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

python3 "$ROOT/elk/setup_elk.py"

if docker container inspect ssh-web-firewall-logstash >/dev/null 2>&1; then
  docker restart ssh-web-firewall-logstash
else
  "${COMPOSE[@]}" up -d logstash
fi
echo "Logstash is starting and will tail the live log and score files."
