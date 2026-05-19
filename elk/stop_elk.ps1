param(
    [switch]$Reset
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$EnvFile = Join-Path $Root "elk\.env"
$ExampleEnvFile = Join-Path $Root "elk\.env.example"
$ComposeFile = Join-Path $Root "elk\docker-compose.yml"

function Ensure-EnvDefaults {
    param(
        [string]$EnvFile,
        [string]$ExampleEnvFile
    )

    $ExistingKeys = @{}
    if (Test-Path $EnvFile) {
        foreach ($Line in Get-Content $EnvFile) {
            $Trimmed = $Line.Trim()
            if ($Trimmed.Length -eq 0 -or $Trimmed.StartsWith("#") -or -not $Trimmed.Contains("=")) {
                continue
            }

            $Key = ($Trimmed -split "=", 2)[0].Trim()
            $ExistingKeys[$Key] = $true
        }
    }

    foreach ($Line in Get-Content $ExampleEnvFile) {
        $Trimmed = $Line.Trim()
        if ($Trimmed.Length -eq 0 -or $Trimmed.StartsWith("#") -or -not $Trimmed.Contains("=")) {
            continue
        }

        $Key = ($Trimmed -split "=", 2)[0].Trim()
        if (-not $ExistingKeys.ContainsKey($Key)) {
            Add-Content -Path $EnvFile -Value $Trimmed
        }
    }
}

if (-not (Test-Path $EnvFile)) {
    Copy-Item $ExampleEnvFile $EnvFile
}

Ensure-EnvDefaults -EnvFile $EnvFile -ExampleEnvFile $ExampleEnvFile

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
