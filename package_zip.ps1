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

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

$zipStream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::Create)
$archive = New-Object System.IO.Compression.ZipArchive($zipStream, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    Get-ChildItem -Path $stagingDir -Recurse -File | ForEach-Object {
        $relPath = $_.FullName.Substring($stagingDir.Length).TrimStart('\', '/')
        $entryName = $relPath.Replace('\', '/')
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $_.FullName, $entryName, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
} finally {
    $archive.Dispose()
    $zipStream.Dispose()
}

$webZipDir = Split-Path $webZipPath
if (!(Test-Path $webZipDir)) { New-Item -ItemType Directory -Path $webZipDir -Force | Out-Null }
if (Test-Path $webZipPath) { Remove-Item $webZipPath -Force }
Copy-Item $zipPath $webZipPath -Force

Remove-Item -Recurse -Force $stagingDir

Write-Host "Successfully packaged: $zipPath"
Write-Host "Successfully synced: $webZipPath"

$desktopZip = 'C:\Users\sfsad\OneDrive\Desktop\vitalssniper_pro.zip'
$desktopVerZip = 'C:\Users\sfsad\OneDrive\Desktop\vitalssniper_v1.4.2_pro.zip'
Copy-Item $zipPath $desktopZip -Force
Copy-Item $zipPath $desktopVerZip -Force
Write-Host "Successfully updated Desktop zips: $desktopZip and $desktopVerZip"
