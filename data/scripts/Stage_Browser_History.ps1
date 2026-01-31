<#
.SYNOPSIS
    Stages browser history database files for download.
.DESCRIPTION
    Copies browser history SQLite databases to a temp location for RTR download.
    Browser files are often locked, so we copy them first.
#>

$ErrorActionPreference = "SilentlyContinue"

# Create staging directory with simple name for easy RTR get
$stagingDir = "C:\Windows\Temp\BH"
if (Test-Path $stagingDir) { Remove-Item -Path $stagingDir -Recurse -Force }
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

$count = 0

# Get all user profiles
$userProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object {
    $_.Name -notin @('Public', 'Default', 'Default User', 'All Users')
}

Write-Output "STAGED_FILES_START"

foreach ($userProfile in $userProfiles) {
    $user = $userProfile.Name
    $userPath = $userProfile.FullName

    # Chrome Default
    $src = "$userPath\AppData\Local\Google\Chrome\User Data\Default\History"
    if (Test-Path $src) {
        $dest = "$stagingDir\Chrome_$user.db"
        Copy-Item -Path $src -Destination $dest -Force 2>$null
        if (Test-Path $dest) {
            Write-Output "Chrome|$user|$dest"
            $count++
        }
    }

    # Edge Default
    $src = "$userPath\AppData\Local\Microsoft\Edge\User Data\Default\History"
    if (Test-Path $src) {
        $dest = "$stagingDir\Edge_$user.db"
        Copy-Item -Path $src -Destination $dest -Force 2>$null
        if (Test-Path $dest) {
            Write-Output "Edge|$user|$dest"
            $count++
        }
    }

    # Firefox (first profile only)
    $ffPath = "$userPath\AppData\Roaming\Mozilla\Firefox\Profiles"
    if (Test-Path $ffPath) {
        $profile = Get-ChildItem $ffPath -Directory | Select-Object -First 1
        if ($profile) {
            $src = "$($profile.FullName)\places.sqlite"
            if (Test-Path $src) {
                $dest = "$stagingDir\Firefox_$user.db"
                Copy-Item -Path $src -Destination $dest -Force 2>$null
                if (Test-Path $dest) {
                    Write-Output "Firefox|$user|$dest"
                    $count++
                }
            }
        }
    }
}

Write-Output "STAGED_FILES_END"
Write-Output "Staged $count files to $stagingDir"
