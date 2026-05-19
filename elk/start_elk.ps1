param(
    [switch]$WithLogstash
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$EnvFile = Join-Path $Root "elk\.env"
$ExampleEnvFile = Join-Path $Root "elk\.env.example"
$ComposeFile = Join-Path $Root "elk\docker-compose.yml"

if (-not (Test-Path $EnvFile)) {
    Copy-Item $ExampleEnvFile $EnvFile
}

$Services = @("elasticsearch", "kibana")
if ($WithLogstash) {
    $Services += "logstash"
}

$ComposeArgs = @("compose", "--env-file", $EnvFile, "-f", $ComposeFile, "up", "-d") + $Services
& docker @ComposeArgs
if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose failed to start ELK services."
}

Write-Host "ELK stack starting."
Write-Host "Elasticsearch: http://localhost:9200"
Write-Host "Kibana:        http://localhost:5601"
Write-Host "After Kibana is reachable, run: .\elk\setup_kibana.ps1"
Write-Host "Logstash starts after setup so index templates exist before ingestion."
