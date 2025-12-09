<#
.SYNOPSIS
    Simple CAPI2 Troubleshooting Workflow Example

.DESCRIPTION
    Demonstrates the basic workflow: Enable log, clear it, test, analyze, and disable.
    
.NOTES
    Author: Jan Tiedemann
    Requires: CAPI2Tools module, Administrator privileges
#>

#Requires -RunAsAdministrator
#Requires -Modules CAPI2Tools

# =============================================================================
# Simple Workflow: Test a Single Certificate Issue
# =============================================================================

# 1. PREPARE: Clear CAPI2 log for clean test
Write-Host "Step 1: Preparing CAPI2 log..." -ForegroundColor Cyan
Start-CAPI2Troubleshooting -ClearLog

# 2. TEST: Reproduce the issue
Write-Host "`nStep 2: Reproduce your TLS/SSL certificate issue now..." -ForegroundColor Yellow
Write-Host "  (Browse to website, run application, etc.)" -ForegroundColor Gray
Read-Host "Press ENTER when done"

# 3. SEARCH: Find events by domain name
Write-Host "`nStep 3: Searching for certificate events..." -ForegroundColor Cyan
$Results = Find-CapiEventsByName -Name "yoursite.com"  # Replace with your domain

# 4. ANALYZE: Check for errors
if ($Results) {
    Write-Host "`nStep 4: Analyzing errors..." -ForegroundColor Cyan
    Get-CapiErrorAnalysis -Events $Results[0].Events -IncludeSummary
    
    # 5. EXPORT: Save results
    Write-Host "`nStep 5: Exporting results..." -ForegroundColor Cyan
    Export-CapiEvents -Events $Results[0].Events `
        -Path "C:\Temp\CertAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').html" `
        -IncludeErrorAnalysis `
        -TaskID $Results[0].TaskID
}

# 6. CLEANUP: Disable logging
Write-Host "`nStep 6: Cleaning up..." -ForegroundColor Cyan
Stop-CAPI2Troubleshooting -DisableLog

Write-Host "`n✓ Done!" -ForegroundColor Green
