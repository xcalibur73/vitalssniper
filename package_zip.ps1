$ErrorActionPreference = 'Stop'
$extDir = Resolve-Path $PSScriptRoot
$workspaceRoot = Split-Path $extDir -Parent
$manifestContent = Get-Content (Join-Path $extDir 'manifest.json') -Raw | ConvertFrom-Json
$version = $manifestContent.version
$zipPath = Join-Path $workspaceRoot 'vitalssniper_pro.zip'
$cwsZipPath = Join-Path $workspaceRoot "vitalssniper_cws_v$version.zip"
$webZipPath = Join-Path $workspaceRoot 'vitalssniper_web\private_releases\vitalssniper_pro.zip'

$stagingDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stagingDir 'icons') -Force | Out-Null

Copy-Item (Join-Path $extDir 'manifest.json') $stagingDir
Copy-Item (Join-Path $extDir 'popup.html') $stagingDir
Copy-Item (Join-Path $extDir 'popup.css') $stagingDir
Copy-Item (Join-Path $extDir 'popup.js') $stagingDir
Copy-Item (Join-Path $extDir 'background.js') $stagingDir
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

# Duplicate clean zip for Chrome Web Store Developer Console upload
Copy-Item $zipPath $cwsZipPath -Force

$webZipDir = Split-Path $webZipPath
if (!(Test-Path $webZipDir)) { New-Item -ItemType Directory -Path $webZipDir -Force | Out-Null }
if (Test-Path $webZipPath) { Remove-Item $webZipPath -Force }
Copy-Item $zipPath $webZipPath -Force

Remove-Item -Recurse -Force $stagingDir

Write-Host "Successfully packaged: $zipPath"
Write-Host "Successfully created CWS upload zip: $cwsZipPath"
Write-Host "Successfully synced: $webZipPath"

# Sync to primary user locations
$targetDirs = @(
    'C:\Users\sfsad\Desktop',
    'C:\Users\sfsad\Downloads',
    'C:\Users\sfsad\OneDrive\Desktop'
)

foreach ($dir in $targetDirs) {
    if (Test-Path $dir) {
        Copy-Item $zipPath (Join-Path $dir 'vitalssniper_pro.zip') -Force
        Copy-Item $zipPath (Join-Path $dir "vitalssniper_v${version}_pro.zip") -Force
        Copy-Item $cwsZipPath (Join-Path $dir "vitalssniper_cws_v${version}.zip") -Force
        Write-Host "Synced vitalssniper_pro.zip and vitalssniper_cws_v${version}.zip to $dir"
    }
}

# Create All-in-One Complete Submission Bundle
$bundleStaging = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $bundleStaging -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $bundleStaging 'store_assets') -Force | Out-Null

Copy-Item $zipPath (Join-Path $bundleStaging 'vitalssniper_pro.zip') -Force
Copy-Item $cwsZipPath (Join-Path $bundleStaging "vitalssniper_cws_v${version}.zip") -Force
Copy-Item (Join-Path $extDir 'STORE_LISTING.md') $bundleStaging -Force
Copy-Item (Join-Path $extDir 'CHROMEWEBSTORE.md') $bundleStaging -Force
Copy-Item (Join-Path $extDir 'README.md') $bundleStaging -Force
Copy-Item (Join-Path $extDir 'store_assets\*.png') (Join-Path $bundleStaging 'store_assets') -Force

$bundleZip = Join-Path $workspaceRoot 'vitalssniper_complete_release_package.zip'
if (Test-Path $bundleZip) { Remove-Item $bundleZip -Force }

$bStream = [System.IO.File]::Open($bundleZip, [System.IO.FileMode]::Create)
$bArchive = New-Object System.IO.Compression.ZipArchive($bStream, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    Get-ChildItem -Path $bundleStaging -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($bundleStaging.Length).TrimStart('\', '/')
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($bArchive, $_.FullName, $rel.Replace('\', '/'), [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
} finally {
    $bArchive.Dispose()
    $bStream.Dispose()
}
Remove-Item -Recurse -Force $bundleStaging

foreach ($dir in $targetDirs) {
    if (Test-Path $dir) {
        Copy-Item $bundleZip (Join-Path $dir 'vitalssniper_complete_release_package.zip') -Force
        $storeAssetsDir = Join-Path $dir 'vitalssniper_store_assets'
        if (!(Test-Path $storeAssetsDir)) { New-Item -ItemType Directory -Path $storeAssetsDir -Force | Out-Null }
        Copy-Item (Join-Path $extDir 'store_assets\*.png') $storeAssetsDir -Force
        Write-Host "Synced complete bundle & store assets to $dir"
    }
}

Write-Host "All distribution packages ready."
