$ErrorActionPreference = "Stop"
$Version   = "1.1.0"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReleaseDir = Join-Path $PSScriptRoot "releases"
$ZipName = "Vertex-Nemesis-SOAR_v${Version}_$Timestamp.zip"
$ZipPath = Join-Path $ReleaseDir $ZipName

if (!(Test-Path $ReleaseDir)) { New-Item -ItemType Directory -Path $ReleaseDir | Out-Null }

# Nunca se empaquetan: venv, libro, bóvedas .duckdb, claves ni __pycache__.
# Se copia a una carpeta temporal, se limpia y se comprime desde ahí.
$Stage = Join-Path $env:TEMP "vertex_soar_release_$Timestamp"
New-Item -ItemType Directory -Path $Stage | Out-Null
$FilesToPack = @("app.py", "client_test.py", "requirements.txt", "README.md", ".gitignore", "Invoke-VertexRelease.ps1", "core", "tests")
foreach ($item in $FilesToPack) {
    Copy-Item -Path (Join-Path $PSScriptRoot $item) -Destination $Stage -Recurse
}
Get-ChildItem -Path $Stage -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
Get-ChildItem -Path $Stage -Recurse -Include *.pyc, *.duckdb, *.key, .env | Remove-Item -Force
Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $ZipPath -Force
Remove-Item -Path $Stage -Recurse -Force

$Hash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash
"$Hash  $ZipName" | Out-File -FilePath "$ZipPath.sha256" -Encoding ascii

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host " VERTEX CODERS LLC - RELEASE v$Version" -ForegroundColor Green
Write-Host " Archivo : $ZipPath"
Write-Host " SHA-256 : $Hash"
Write-Host " (hash guardado en $ZipName.sha256)"
Write-Host "========================================================`n" -ForegroundColor Cyan
