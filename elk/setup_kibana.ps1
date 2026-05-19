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

foreach ($Line in Get-Content $EnvFile) {
    $Trimmed = $Line.Trim()
    if ($Trimmed.Length -eq 0 -or $Trimmed.StartsWith("#") -or -not $Trimmed.Contains("=")) {
        continue
    }

    $Parts = $Trimmed -split "=", 2
    Set-Item -Path "Env:$($Parts[0].Trim())" -Value $Parts[1].Trim()
}

& python (Join-Path $Root "elk\setup_elk.py")
if ($LASTEXITCODE -ne 0) {
    throw "Kibana setup failed."
}

$LogstashName = "ssh-web-firewall-logstash"
$LogstashNames = @(& docker ps -a --filter "name=$LogstashName" --format "{{.Names}}")
if ($LASTEXITCODE -ne 0) {
    throw "Could not check Logstash container state."
}

$LogstashExists = $LogstashNames -contains $LogstashName

if ($LogstashExists) {
    & docker restart $LogstashName
} else {
    & docker compose --env-file $EnvFile -f $ComposeFile up -d logstash
}

if ($LASTEXITCODE -ne 0) {
    throw "Logstash start/restart failed."
}

Write-Host "Logstash is starting and will tail the live log and score files."
