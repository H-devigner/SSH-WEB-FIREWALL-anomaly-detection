param(
    [switch]$Reset
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$EnvFile = Join-Path $Root "elk\.env"
$ExampleEnvFile = Join-Path $Root "elk\.env.example"
$ComposeFile = Join-Path $Root "elk\docker-compose.yml"

if (-not (Test-Path $EnvFile)) {
    Copy-Item $ExampleEnvFile $EnvFile
}

$ComposeArgs = @("compose", "--env-file", $EnvFile, "-f", $ComposeFile, "down")
if ($Reset) {
    $ComposeArgs += "-v"
}

& docker @ComposeArgs
if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose failed to stop ELK services."
}

if ($Reset) {
    Write-Host "ELK stack stopped and volumes removed."
} else {
    Write-Host "ELK stack stopped. Run with -Reset to remove Elasticsearch and Logstash volumes."
}
