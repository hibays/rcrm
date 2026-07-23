# build_clean.ps1
# Clean build artifacts using native tool clean commands.
# Usage:
#   .\scripts\build_clean.ps1          # clean everything
#   .\scripts\build_clean.ps1 -DryRun  # preview only
param([switch]$DryRun)

$root = $PSScriptRoot | Split-Path -Parent
$gui = "$root\crates\rcrm-gui"
$bridge = "$root\crates\rcrm-flutter-bridge"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " RCrm GUI --- Clean Build Artifacts" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

function Run-Cmd([string]$Label, [scriptblock]$Cmd) {
    if ($DryRun) {
        Write-Host "  [dry]   $Label" -ForegroundColor Yellow
        return
    }
    Write-Host "  [clean] $Label" -ForegroundColor Green
    & $Cmd
}

# ── Rust ───────────────────────────────────────────────────────
Run-Cmd "cargo clean (rcrm-flutter-bridge)" {
    Push-Location $bridge; cargo clean; Pop-Location
}
Write-Host ""

# ── Flutter (handles all platforms) ────────────────────────────
Run-Cmd "flutter clean (rcrm-gui)" {
    Push-Location $gui; flutter clean; Pop-Location
}
Write-Host ""

# ── Android Gradle ─────────────────────────────────────────────
$gradlew = "$gui\android\gradlew"
$gradlewBat = "$gui\android\gradlew.bat"
if (Test-Path $gradlewBat) {
    Run-Cmd "gradlew clean (android)" {
        Push-Location "$gui\android"; & .\gradlew.bat clean; Pop-Location
    }
    Write-Host ""
}

# ── Android jniLibs (Rust .so output) ──────────────────────────
$jniLibs = "$gui\android\app\src\main\jniLibs"
if (Test-Path $jniLibs) {
    if ($DryRun) {
        $size = (Get-ChildItem $jniLibs -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        $sizeMB = '{0:N1} MB' -f ($size / 1MB)
        Write-Host "  [dry]   jniLibs/  $sizeMB" -ForegroundColor Yellow
    } else {
        Remove-Item $jniLibs -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  [del]   jniLibs/" -ForegroundColor Green
    }
    Write-Host ""
}

if ($DryRun) {
    Write-Host "Dry run complete — no files changed." -ForegroundColor Yellow
} else {
    Write-Host "Done." -ForegroundColor Green
}
