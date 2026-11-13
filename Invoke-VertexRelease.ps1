$ErrorActionPreference = "Stop"
$Version   = "1.1.0"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReleaseDir = Join-Path $PSScriptRoot "releases"
$ZipName = "Vertex-Nemesis-SOAR_v${Version}_$Timestamp.zip"
$ZipPath = Join-Path $ReleaseDir $ZipName

if (!(Test-Path $ReleaseDir)) { New-Item -ItemType Directory -Path $ReleaseDir | Out-Null }

# Nunca se empaquetan: venv, libro, bóvedas .duckdb ni claves
$FilesToPack = @("app.py", "client_test.py", "requirements.txt", "README.md", ".gitignore", "core", "tests") |
    ForEach-Object { Join-Path $PSScriptRoot $_ }
Compress-Archive -Path $FilesToPack -DestinationPath $ZipPath -Force

$Hash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash
"$Hash  $ZipName" | Out-File -FilePath "$ZipPath.sha256" -Encoding ascii

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host " VERTEX CODERS LLC - RELEASE v$Version" -ForegroundColor Green
Write-Host " Archivo : $ZipPath"
Write-Host " SHA-256 : $Hash"
Write-Host " (hash guardado en $ZipName.sha256)"
Write-Host "========================================================`n" -ForegroundColor Cyan
