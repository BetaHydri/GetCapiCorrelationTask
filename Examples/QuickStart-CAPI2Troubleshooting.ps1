<#
.SYNOPSIS
    Quick Start Example for CAPI2Tools Module

.DESCRIPTION
    This script demonstrates the complete workflow for troubleshooting
    certificate issues using the CAPI2Tools PowerShell module.

.NOTES
    Author: Jan Tiedemann
    Version: 1.0
    Requires: CAPI2Tools module, Administrator privileges
#>

#Requires -RunAsAdministrator
#Requires -Modules CAPI2Tools

# Helper function for display characters
Function Get-Char {
    param([ValidateSet('Check', 'BoxTL', 'BoxTR', 'BoxBL', 'BoxBR', 'BoxV', 'BoxH')]$Name)
    switch ($Name) {
        'Check' { [char]0x2713 }  # ✓
        'BoxTL' { [char]0x2554 }  # ╔
        'BoxTR' { [char]0x2557 }  # ╗
        'BoxBL' { [char]0x255A }  # ╚
        'BoxBR' { [char]0x255D }  # ╝
        'BoxV'  { [char]0x2551 }  # ║
        'BoxH'  { [char]0x2550 }  # ═
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

Write-BoxHeader "CAPI2 Certificate Troubleshooting - Quick Start"

# =============================================================================
# WORKFLOW: Certificate Troubleshooting Session
# =============================================================================

# Step 1: Start fresh troubleshooting session
Write-Host "`n### STEP 1: Prepare CAPI2 Event Log ###`n" -ForegroundColor Yellow

# Option A: Start with existing events (for analysis)
# Start-CAPI2Troubleshooting

# Option B: Clear log for clean test (recommended for new issues)
Start-CAPI2Troubleshooting -ClearLog -BackupPath "C:\Temp\CAPI2_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"

# ------------------------------------------------------------------------------

# Step 2: Reproduce the certificate issue
Write-Host "`n### STEP 2: Reproduce Your Certificate Issue ###`n" -ForegroundColor Yellow
Write-Host "Now do one of the following:" -ForegroundColor White
Write-Host "  • Browse to the failing HTTPS website" -ForegroundColor Gray
Write-Host "  • Run the application that has certificate errors" -ForegroundColor Gray
Write-Host "  • Test the TLS/SSL connection" -ForegroundColor Gray

Read-Host "`nPress ENTER after reproducing the issue"

# ------------------------------------------------------------------------------

# Step 3: Search for events by DNS name
Write-Host "`n### STEP 3: Search for Certificate Events ###`n" -ForegroundColor Yellow

# Prompt for the domain name
$DomainName = Read-Host "Enter the domain name or certificate subject (e.g., 'microsoft.com', '*.contoso.com')"

# Search for events
Write-Host "`nSearching for events..." -ForegroundColor Cyan
$Results = Find-CapiEventsByName -Name $DomainName -Hours 1

if ($Results) {
    Write-Host "`nFound $($Results.Count) correlation chain(s)" -ForegroundColor Green
    
    # Display summary
    $Results | Format-Table @{L='#';E={$Results.IndexOf($_)}}, TaskID, TimeCreated, EventCount -AutoSize
    
    # Select which chain to analyze
    if ($Results.Count -gt 1) {
        $Selection = Read-Host "`nEnter the number of the chain to analyze (0-$($Results.Count-1))"
        $SelectedChain = $Results[[int]$Selection]
    } else {
        $SelectedChain = $Results[0]
    }
    
    # ------------------------------------------------------------------------------
    
    # Step 4: Analyze errors
    Write-Host "`n### STEP 4: Analyze Certificate Errors ###`n" -ForegroundColor Yellow
    
    Get-CapiErrorAnalysis -Events $SelectedChain.Events -IncludeSummary | Out-Null
    
    # ------------------------------------------------------------------------------
    
    # Step 5: Export results
    Write-Host "`n### STEP 5: Export Results for Documentation ###`n" -ForegroundColor Yellow
    
    $ExportChoice = Read-Host "Export results? (Y/N)"
    
    if ($ExportChoice -eq 'Y') {
        $ExportFolder = "C:\Temp\CAPI2Reports"
        if (!(Test-Path $ExportFolder)) {
            New-Item -Path $ExportFolder -ItemType Directory -Force | Out-Null
        }
        
        $Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $BaseName = "$ExportFolder\CAPI2_${DomainName}_$Timestamp"
        
        # Export to multiple formats
        Write-Host "`nExporting to multiple formats..." -ForegroundColor Cyan
        
        Export-CapiEvents -Events $SelectedChain.Events -Path "$BaseName.html" -IncludeErrorAnalysis -TaskID $SelectedChain.TaskID
        Export-CapiEvents -Events $SelectedChain.Events -Path "$BaseName.json" -IncludeErrorAnalysis -TaskID $SelectedChain.TaskID
        Export-CapiEvents -Events $SelectedChain.Events -Path "$BaseName.csv" -TaskID $SelectedChain.TaskID
        
        Write-Host "`n$(Get-Char Check) Reports saved to: $ExportFolder" -ForegroundColor Green
        
        # Open HTML report
        $OpenReport = Read-Host "Open HTML report? (Y/N)"
        if ($OpenReport -eq 'Y') {
            Start-Process "$BaseName.html"
        }
    }
    
    # ------------------------------------------------------------------------------
    
    # Step 6: Optional - Compare before/after fix
    Write-Host "`n### STEP 6: (Optional) Test Fix and Compare ###`n" -ForegroundColor Yellow
    
    $TestFix = Read-Host "Did you apply a fix and want to test again? (Y/N)"
    
    if ($TestFix -eq 'Y') {
        Write-Host "`nPlease reproduce the issue again after your fix..." -ForegroundColor Cyan
        Read-Host "Press ENTER after reproducing"
        
        # Search again
        $ResultsAfter = Find-CapiEventsByName -Name $DomainName -Hours 1
        
        if ($ResultsAfter) {
            # Compare
            Compare-CapiEvents `
                -ReferenceEvents $SelectedChain.Events `
                -DifferenceEvents $ResultsAfter[0].Events `
                -ReferenceLabel "Before Fix" `
                -DifferenceLabel "After Fix"
        }
    }
    
} else {
    Write-Warning "No events found for '$DomainName'"
    Write-Host "Suggestions:" -ForegroundColor Yellow
    Write-Host "  • Make sure CAPI2 logging is enabled" -ForegroundColor Gray
    Write-Host "  • Verify the certificate operation actually occurred" -ForegroundColor Gray
    Write-Host "  • Try increasing the -Hours parameter" -ForegroundColor Gray
}

# ------------------------------------------------------------------------------

# Step 7: Complete the session
Write-Host "`n### STEP 7: Complete Troubleshooting Session ###`n" -ForegroundColor Yellow

$DisableChoice = Read-Host "Disable CAPI2 logging? (Y/N)"

if ($DisableChoice -eq 'Y') {
    Stop-CAPI2Troubleshooting -DisableLog
} else {
    Stop-CAPI2Troubleshooting
}

Write-BoxHeader "Troubleshooting session complete! Thank you for using CAPI2Tools"
