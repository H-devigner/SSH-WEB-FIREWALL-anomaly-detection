#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/elk/.env"
COMPOSE_FILE="$ROOT/elk/docker-compose.yml"
COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")

if [ ! -f "$ENV_FILE" ]; then
  cp "$ROOT/elk/.env.example" "$ENV_FILE"
fi

SERVICES=(elasticsearch kibana)
if [ "${1:-}" = "--with-logstash" ]; then
  SERVICES+=(logstash)
fi

"${COMPOSE[@]}" up -d "${SERVICES[@]}"

echo "ELK stack starting."
echo "Elasticsearch: http://localhost:9200"
echo "Kibana:        http://localhost:5601"
echo "After Kibana is reachable, run: elk/setup_kibana.sh"
echo "Logstash starts after setup so index templates exist before ingestion."
