Write-Host "Starting Asset Management System..." -ForegroundColor Green
Write-Host ""
Write-Host "This will start the Flask server on http://localhost:5000" -ForegroundColor Yellow
Write-Host ""
Write-Host "To access the application, open your browser and go to:" -ForegroundColor Cyan
Write-Host "http://localhost:5000" -ForegroundColor White
Write-Host ""
Write-Host "Default login credentials:" -ForegroundColor Cyan
Write-Host "Username: admin" -ForegroundColor White
Write-Host "Password: admin123" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Always run from the script directory so relative files like backend.py and *.json resolve correctly.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -Path $scriptDir

# Prefer the Python launcher on Windows, then fall back to python/python3 if available.
$pythonCommand = $null
foreach ($candidate in @("py", "python", "python3")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $pythonCommand = $candidate
        break
    }
}

if (-not $pythonCommand) {
    Write-Host "Python was not found. Install Python 3 and try again." -ForegroundColor Red
    Write-Host "Tip: after installing Python, reopen PowerShell and run .\start_server.ps1" -ForegroundColor Yellow
    exit 1
}

# Start the Flask server.
& $pythonCommand ".\backend.py"
