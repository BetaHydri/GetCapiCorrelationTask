<#
.SYNOPSIS
    Advanced Example: Before/After Comparison Workflow

.DESCRIPTION
    Demonstrates how to compare certificate validation before and after applying a fix.
    
.NOTES
    Author: Jan Tiedemann
    Requires: CAPI2Tools module, Administrator privileges
#>

#Requires -RunAsAdministrator
#Requires -Modules CAPI2Tools

# Helper function for display characters
Function Get-Char {
    param([ValidateSet('Check', 'Warning', 'Arrow', 'BoxTL', 'BoxTR', 'BoxBL', 'BoxBR', 'BoxV', 'BoxH')]$Name)
    switch ($Name) {
        'Check'   { [char]0x2713 }  # ✓
        'Warning' { [char]0x26A0 }  # ⚠
        'Arrow'   { [char]0x2192 }  # →
        'BoxTL'   { [char]0x2554 }  # ╔
        'BoxTR'   { [char]0x2557 }  # ╗
        'BoxBL'   { [char]0x255A }  # ╚
        'BoxBR'   { [char]0x255D }  # ╝
        'BoxV'    { [char]0x2551 }  # ║
        'BoxH'    { [char]0x2550 }  # ═
    }
}

Function Write-BoxHeader {
    param([string]$Text)
    $Width = 63; $Line = (Get-Char BoxH) * $Width
    $PaddingLeft = [Math]::Floor(($Width - $Text.Length) / 2)
    $PaddingRight = $Width - $Text.Length - $PaddingLeft
    Write-Host "`n$(Get-Char BoxTL)$Line$(Get-Char BoxTR)" -ForegroundColor Cyan
    Write-Host "$(Get-Char BoxV)$(' ' * $PaddingLeft)$Text$(' ' * $PaddingRight)$(Get-Char BoxV)" -ForegroundColor Cyan
    Write-Host "$(Get-Char BoxBL)$Line$(Get-Char BoxBR)`n" -ForegroundColor Cyan
}

# =============================================================================
# Advanced Workflow: Compare Certificate Validation Before & After Fix
# =============================================================================

$Domain = "problematic-site.com"  # Replace with your domain

# Phase 1: BEFORE FIX - Capture baseline
Write-BoxHeader "PHASE 1: Capture BEFORE state"

# Prepare log
Start-CAPI2Troubleshooting -ClearLog
Write-Host "Reproduce the certificate issue..." -ForegroundColor Yellow
Read-Host "Press ENTER when done"

# Capture BEFORE state
Write-Host "`nCapturing BEFORE state..." -ForegroundColor Cyan
$BeforeResults = Find-CapiEventsByName -Name $Domain -Hours 1

if (!$BeforeResults) {
    Write-Error "No events found for '$Domain'. Exiting."
    exit
}

$BeforeEvents = $BeforeResults[0].Events

Write-Host "$(Get-Char Check) Captured $($BeforeEvents.Count) events before fix" -ForegroundColor Green

# Analyze BEFORE errors
Write-Host "\nBEFORE Fix - Error Analysis:" -ForegroundColor Yellow
Get-CapiErrorAnalysis -Events $BeforeEvents -IncludeSummary | Out-Null

# Export BEFORE state
$ReportFolder = "C:\Temp\CAPI2Comparison_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $ReportFolder -ItemType Directory -Force | Out-Null

Export-CapiEvents -Events $BeforeEvents `
    -Path "$ReportFolder\Before_Fix.html" `
    -IncludeErrorAnalysis `
    -TaskID $BeforeResults[0].TaskID

# ------------------------------------------------------------------------------

# Phase 2: APPLY FIX
Write-BoxHeader "PHASE 2: Apply your fix"

Write-Host "Now apply your certificate fix:" -ForegroundColor Yellow
Write-Host "  * Install missing intermediate certificate" -ForegroundColor Gray
Write-Host "  * Renew expired certificate" -ForegroundColor Gray
Write-Host "  * Fix certificate chain" -ForegroundColor Gray
Write-Host "  * Update trusted roots" -ForegroundColor Gray
Write-Host "  * etc." -ForegroundColor Gray

Read-Host "`nPress ENTER after applying the fix"

# ------------------------------------------------------------------------------

# Phase 3: AFTER FIX - Capture new state
Write-BoxHeader "PHASE 3: Capture AFTER state"

# Clear log for clean AFTER test
Clear-CAPI2EventLog
Write-Host "Reproduce the same operation again..." -ForegroundColor Yellow
Read-Host "Press ENTER when done"

# Capture AFTER state
Write-Host "`nCapturing AFTER state..." -ForegroundColor Cyan
$AfterResults = Find-CapiEventsByName -Name $Domain -Hours 1

if (!$AfterResults) {
    Write-Warning "No events found after fix. The operation may not have occurred."
    Stop-CAPI2Troubleshooting -DisableLog
    exit
}

$AfterEvents = $AfterResults[0].Events

Write-Host "$(Get-Char Check) Captured $($AfterEvents.Count) events after fix" -ForegroundColor Green

# Analyze AFTER errors
Write-Host "\nAFTER Fix - Error Analysis:" -ForegroundColor Yellow
Get-CapiErrorAnalysis -Events $AfterEvents -IncludeSummary | Out-Null

# Export AFTER state
Export-CapiEvents -Events $AfterEvents `
    -Path "$ReportFolder\After_Fix.html" `
    -IncludeErrorAnalysis `
    -TaskID $AfterResults[0].TaskID

# ------------------------------------------------------------------------------

# Phase 4: COMPARE
Write-BoxHeader "PHASE 4: Compare Before vs After"

# Perform comparison
Compare-CapiEvents `
    -ReferenceEvents $BeforeEvents `
    -DifferenceEvents $AfterEvents `
    -ReferenceLabel "BEFORE Fix" `
    -DifferenceLabel "AFTER Fix"

# Create comparison summary
$ComparisonSummary = @"
# Certificate Troubleshooting Comparison Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Domain: $Domain

## Before Fix
- Events: $($BeforeEvents.Count)
- Errors: $($BeforeErrors.Count)

## After Fix
- Events: $($AfterEvents.Count)
- Errors: $($AfterErrors.Count)

## Reports Location
$ReportFolder

## Files
- Before_Fix.html - Detailed BEFORE analysis
- After_Fix.html - Detailed AFTER analysis
- Comparison_Summary.txt - This file

## Recommendation
$(if ($AfterErrors.Count -lt $BeforeErrors.Count) { "$(Get-Char Check) Fix was successful! Errors reduced." } 
  elseif ($AfterErrors.Count -eq 0 -and $BeforeErrors.Count -gt 0) { "$(Get-Char Check) All errors resolved!" }
  elseif ($AfterErrors.Count -gt $BeforeErrors.Count) { "$(Get-Char Warning) Situation worsened. Review fix." }
  else { "$(Get-Char Arrow) No change in error count. Additional troubleshooting needed." })
"@

$ComparisonSummary | Out-File "$ReportFolder\Comparison_Summary.txt" -Encoding UTF8

Write-Host "`n$(Get-Char Check) Comparison complete!" -ForegroundColor Green
Write-Host "  Reports saved to: $ReportFolder" -ForegroundColor Gray

# Open reports
$OpenReports = Read-Host "`nOpen comparison reports? (Y/N)"
if ($OpenReports -eq 'Y') {
    Start-Process "$ReportFolder\Before_Fix.html"
    Start-Process "$ReportFolder\After_Fix.html"
    Start-Process "$ReportFolder\Comparison_Summary.txt"
}

# Cleanup
Stop-CAPI2Troubleshooting -DisableLog

Write-BoxHeader "$(Get-Char Check) Comparison workflow complete!"
