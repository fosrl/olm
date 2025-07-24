# Olm Windows Service Management Script
# This PowerShell script helps manage the Olm WireGuard service on Windows

param(
    [Parameter(Position=0)]
    [ValidateSet("install", "remove", "uninstall", "start", "stop", "status", "debug", "help")]
    [string]$Command = "help"
)

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Help {
    Write-Host "Olm WireGuard Service Management" -ForegroundColor Green
    Write-Host ""
    Write-Host "Usage: .\olm-service.ps1 [command]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Commands:" -ForegroundColor Yellow
    Write-Host "  install     Install the Olm service"
    Write-Host "  remove      Remove the Olm service"
    Write-Host "  start       Start the Olm service"
    Write-Host "  stop        Stop the Olm service"
    Write-Host "  status      Show service status"
    Write-Host "  debug       Run in debug mode"
    Write-Host "  help        Show this help"
    Write-Host ""
    Write-Host "Note: This script must be run as Administrator for service management." -ForegroundColor Red
    Write-Host "Make sure olm.exe is in your PATH or in the same directory." -ForegroundColor Yellow
}

function Invoke-OlmCommand {
    param([string]$cmd)
    
    if (-not (Test-Administrator) -and $cmd -ne "status" -and $cmd -ne "help") {
        Write-Error "This script must be run as Administrator for service management."
        Write-Host "Right-click PowerShell and select 'Run as administrator'" -ForegroundColor Yellow
        return $false
    }

    try {
        $olmPath = Get-Command "olm.exe" -ErrorAction SilentlyContinue
        if (-not $olmPath) {
            # Try current directory
            $olmPath = Join-Path $PSScriptRoot "olm.exe"
            if (-not (Test-Path $olmPath)) {
                Write-Error "olm.exe not found in PATH or current directory"
                return $false
            }
        } else {
            $olmPath = $olmPath.Source
        }

        Write-Host "Executing: $olmPath $cmd" -ForegroundColor Cyan
        $result = & $olmPath $cmd
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host $result -ForegroundColor Green
            Write-Host "Operation completed successfully." -ForegroundColor Green
            return $true
        } else {
            Write-Error "Command failed with exit code: $LASTEXITCODE"
            Write-Host $result -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Error "Failed to execute olm.exe: $($_.Exception.Message)"
        return $false
    }
}

# Main execution
switch ($Command.ToLower()) {
    "help" {
        Show-Help
    }
    default {
        $success = Invoke-OlmCommand -cmd $Command
        if (-not $success) {
            exit 1
        }
    }
}
