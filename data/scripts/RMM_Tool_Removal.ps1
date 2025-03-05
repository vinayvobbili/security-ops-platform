# Script to detect and remove common RMM tools
# Logging setup
$logPath = "C:\Windows\Temp\rmm_cleanup.log"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Common RMM process names and service names
$rmmProcesses = @(
    "ScreenConnect",
    "TeamViewer",
    "AnyDesk",
    "VNCServer",
    "RemotePC",
    "ConnectWise",
    "Splashtop",
    "LogMeIn",
    "RAdmin"
)

# Function to write to log
function Write-Log {
    param($Message)
    "$timestamp - $Message" | Out-File -FilePath $logPath -Append
}

Write-Log "Starting RMM detection and cleanup"

# Check for running processes
foreach ($process in $rmmProcesses) {
    $foundProcesses = Get-Process | Where-Object {$_.ProcessName -like "*$process*"}
    if ($foundProcesses) {
        foreach ($proc in $foundProcesses) {
            Write-Log "Found RMM process: $($proc.ProcessName)"
            try {
                Stop-Process -Id $proc.Id -Force
                Write-Log "Successfully terminated process: $($proc.ProcessName)"
            }
            catch {
                Write-Log "Error terminating process $($proc.ProcessName): $_"
            }
        }
    }
}

# Check for services
foreach ($service in $rmmProcesses) {
    $foundServices = Get-Service | Where-Object {$_.Name -like "*$service*"}
    if ($foundServices) {
        foreach ($svc in $foundServices) {
            Write-Log "Found RMM service: $($svc.Name)"
            try {
                Stop-Service -Name $svc.Name -Force
                Set-Service -Name $svc.Name -StartupType Disabled
                Write-Log "Successfully stopped and disabled service: $($svc.Name)"
            }
            catch {
                Write-Log "Error stopping service $($svc.Name): $_"
            }
        }
    }
}

# Common RMM installation paths
$commonPaths = @(
    "C:\Program Files\*",
    "C:\Program Files (x86)\*",
    "C:\ProgramData\*"
    "C:\temp/*"
)

# Search and remove RMM software folders
foreach ($basePath in $commonPaths) {
    foreach ($rmm in $rmmProcesses) {
        $rmmPaths = Get-ChildItem -Path $basePath -Directory -Filter "*$rmm*" -ErrorAction SilentlyContinue
        foreach ($path in $rmmPaths) {
            Write-Log "Found RMM installation: $($path.FullName)"
            try {
                Remove-Item -Path $path.FullName -Recurse -Force
                Write-Log "Successfully removed installation: $($path.FullName)"
            }
            catch {
                Write-Log "Error removing installation $($path.FullName): $_"
            }
        }
    }
}

Write-Log "RMM detection and cleanup completed"

# Display final message
Write-Host "RMM cleanup complete. Check $logPath for detailed log."