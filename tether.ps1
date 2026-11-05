[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$ReleaseBin = Join-Path $ScriptDir "target\release\tether.exe"
$DebugBin = Join-Path $ScriptDir "target\debug\tether.exe"

if (-not (Test-Path $ReleaseBin) -and -not (Test-Path $DebugBin)) {
    Write-Host "[tether] Compiling release binary..." -ForegroundColor Cyan
    Push-Location $ScriptDir
    try {
        cargo build --release
    } finally {
        Pop-Location
    }
}

$Bin = if (Test-Path $ReleaseBin) { $ReleaseBin } else { $DebugBin }

if ($Arguments.Length -gt 0 -and $Arguments[0] -eq "demo") {
    Write-Host "=== TideOS Eval Kit Tool 15: tether Demo ===" -ForegroundColor Green
    & $Bin table
    Write-Host "`n=== Evaluating Better Model Release Candidate ===" -ForegroundColor Yellow
    & $Bin release --spec (Join-Path $ScriptDir "packs\softfactory.toml") --baseline (Join-Path $ScriptDir "packs\fixtures\baseline_runs.jsonl") --candidate (Join-Path $ScriptDir "packs\fixtures\candidate_better.jsonl")
    Write-Host "`n=== Evaluating Silent Category Regression Candidate ===" -ForegroundColor Yellow
    & $Bin release --spec (Join-Path $ScriptDir "packs\softfactory.toml") --baseline (Join-Path $ScriptDir "packs\fixtures\baseline_runs.jsonl") --candidate (Join-Path $ScriptDir "packs\fixtures\candidate_silent_regression.jsonl")
    Write-Host "`n=== Evaluating Dev-Overfit Held-Out Regression Candidate ===" -ForegroundColor Yellow
    & $Bin release --spec (Join-Path $ScriptDir "packs\softfactory.toml") --baseline (Join-Path $ScriptDir "packs\fixtures\baseline_runs.jsonl") --candidate (Join-Path $ScriptDir "packs\fixtures\candidate_overfit_dev_only.jsonl")
} else {
    & $Bin @Arguments
}
