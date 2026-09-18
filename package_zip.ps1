$ErrorActionPreference = 'Stop'
$extDir = Resolve-Path $PSScriptRoot
$zipPath = 'b:\Project Seo for WU and AA\projects\micro_saas_extensions\vitalssniper_pro.zip'
$webZipPath = 'b:\Project Seo for WU and AA\projects\micro_saas_extensions\vitalssniper_web\private_releases\vitalssniper_pro.zip'

$stagingDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stagingDir 'icons') -Force | Out-Null

Copy-Item (Join-Path $extDir 'manifest.json') $stagingDir
Copy-Item (Join-Path $extDir 'popup.html') $stagingDir
Copy-Item (Join-Path $extDir 'popup.css') $stagingDir
Copy-Item (Join-Path $extDir 'popup.js') $stagingDir
Copy-Item (Join-Path $extDir 'background.js') $stagingDir
Copy-Item (Join-Path $extDir 'ExtPay.js') $stagingDir
Copy-Item (Join-Path $extDir 'README.md') $stagingDir
Copy-Item (Join-Path $extDir 'icons\*') (Join-Path $stagingDir 'icons')

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path (Join-Path $stagingDir '*') -DestinationPath $zipPath -CompressionLevel Optimal

if (Test-Path $webZipPath) { Remove-Item $webZipPath -Force }
Copy-Item $zipPath $webZipPath -Force

Remove-Item -Recurse -Force $stagingDir

Write-Host "Successfully packaged: $zipPath"
Write-Host "Successfully synced: $webZipPath"
