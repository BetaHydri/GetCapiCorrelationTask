<#
.SYNOPSIS
    Integration/E2E test script for CAPI2Tools module validation
    
.DESCRIPTION
    This is an INTEGRATION TEST script that validates the module with real-world scenarios.
    
    Unlike the Pester unit tests (Tests/CAPI2Tools.Tests.ps1) which run fast automated tests
    with mock data, this script performs end-to-end validation by:
    
    1. Importing the module
    2. Enabling CAPI2 logging (requires admin)
    3. Generating REAL certificate events by connecting to live websites
    4. Analyzing the captured events from the actual event log
    5. Testing all export formats with real data
    6. Cleaning up
    
    WHEN TO USE:
    - Before releases to validate real-world functionality
    - Manual testing and demonstrations
    - Troubleshooting module behavior with actual certificate chains
    - Verifying event log integration works correctly
    
    FOR FAST AUTOMATED TESTING:
    - Use: Invoke-Pester -Path .\Tests\CAPI2Tools.Tests.ps1
    - No admin required, runs in ~1.5 seconds
    - Perfect for CI/CD and development
    
.NOTES
    Author: Jan Tiedemann
    Date: December 2025
    Type: Integration/E2E Testing
    Requires: Administrator privileges, Internet access
    Related: Tests/CAPI2Tools.Tests.ps1 (Pester unit tests)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$KeepLogEnabled,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportFolder = "C:\Temp\CAPI2Tests"
)

# Test websites with different certificate characteristics
$TestWebsites = @(
    @{Name = "microsoft.com"; Expected = "Valid certificate" }
    @{Name = "github.com"; Expected = "Valid certificate with GitHub CA" }
    @{Name = "google.com"; Expected = "Valid certificate with Google Trust Services" }
    @{Name = "expired.badssl.com"; Expected = "Expired certificate (should fail)" }
)

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                              ║" -ForegroundColor Cyan
Write-Host "║        CAPI2Tools Module - Integration Test Suite           ║" -ForegroundColor Cyan
Write-Host "║                                                              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Error "This test script requires administrative privileges. Please run PowerShell as Administrator."
    exit 1
}

#region Test 1: Module Import
Write-Host "`n[TEST 1] Module Import" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

try {
    # Get the module path
    $ModulePath = Join-Path $PSScriptRoot "CAPI2Tools.psm1"
    
    if (-not (Test-Path $ModulePath)) {
        throw "Module not found at: $ModulePath"
    }
    
    Write-Host "  Importing module from: $ModulePath" -ForegroundColor Gray
    Import-Module $ModulePath -Force -ErrorAction Stop
    
    # Verify module loaded
    $Module = Get-Module CAPI2Tools
    if ($Module) {
        Write-Host "  ✓ Module imported successfully" -ForegroundColor Green
        Write-Host "    Version: $($Module.Version)" -ForegroundColor Gray
        Write-Host "    Commands: $($Module.ExportedCommands.Count)" -ForegroundColor Gray
    }
    else {
        throw "Module failed to load"
    }
}
catch {
    Write-Host "  ✗ FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
#endregion

#region Test 2: Enable CAPI2 Logging
Write-Host "`n[TEST 2] Enable CAPI2 Event Logging" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

try {
    Enable-CAPI2EventLog
    Start-Sleep -Seconds 2
    
    # Verify it's enabled
    $LogDetails = wevtutil.exe gl Microsoft-Windows-CAPI2/Operational
    if ($LogDetails -match "enabled:\s+true") {
        Write-Host "  ✓ CAPI2 logging enabled successfully" -ForegroundColor Green
    }
    else {
        throw "CAPI2 logging is not enabled"
    }
}
catch {
    Write-Host "  ✗ FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
#endregion

#region Test 3: Clear Event Log
Write-Host "`n[TEST 3] Clear CAPI2 Event Log" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

try {
    Clear-CAPI2EventLog -ErrorAction Stop
    Write-Host "  ✓ Event log cleared successfully" -ForegroundColor Green
}
catch {
    Write-Host "  ✗ FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
#endregion

#region Test 4: Generate Certificate Events
Write-Host "`n[TEST 4] Generate Certificate Validation Events" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

foreach ($Site in $TestWebsites) {
    Write-Host "`n  Testing: $($Site.Name)" -ForegroundColor Cyan
    Write-Host "  Expected: $($Site.Expected)" -ForegroundColor Gray
    
    try {
        # Try to connect to the website to trigger certificate validation
        $Result = Invoke-WebRequest -Uri "https://$($Site.Name)" -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
        
        if ($Result.StatusCode -eq 200) {
            Write-Host "    ✓ Connection successful (Status: $($Result.StatusCode))" -ForegroundColor Green
        }
    }
    catch {
        # Expected for sites like expired.badssl.com
        if ($Site.Name -match "badssl") {
            Write-Host "    ✓ Connection failed as expected (certificate issue)" -ForegroundColor Yellow
        }
        else {
            Write-Host "    ! Connection failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    Start-Sleep -Seconds 2
}

Write-Host "`n  Waiting 5 seconds for events to be written..." -ForegroundColor Gray
Start-Sleep -Seconds 5
#endregion

#region Test 5: Check Event Log Status
Write-Host "`n[TEST 5] Verify Events Were Generated" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

try {
    Get-CAPI2EventLogStatus
    
    $EventCount = (Get-WinEvent -LogName Microsoft-Windows-CAPI2/Operational -ErrorAction SilentlyContinue | Measure-Object).Count
    
    if ($EventCount -gt 0) {
        Write-Host "  ✓ Generated $EventCount CAPI2 events" -ForegroundColor Green
    }
    else {
        throw "No events were generated"
    }
}
catch {
    Write-Host "  ✗ FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
#endregion

#region Test 6: Search Events by Name
Write-Host "`n[TEST 6] Search Events by Certificate Name" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

$TestResults = @()

foreach ($Site in $TestWebsites | Where-Object { $_.Name -notmatch "badssl" }) {
    Write-Host "`n  Searching for: $($Site.Name)" -ForegroundColor Cyan
    
    try {
        $Results = Find-CapiEventsByName -Name $Site.Name -Hours 1 -ErrorAction Stop
        
        if ($Results) {
            Write-Host "    ✓ Found $($Results.Count) correlation chain(s)" -ForegroundColor Green
            Write-Host "      TaskID: $($Results[0].TaskID)" -ForegroundColor Gray
            Write-Host "      Events: $($Results[0].EventCount)" -ForegroundColor Gray
            
            $TestResults += [PSCustomObject]@{
                Website    = $Site.Name
                Found      = $true
                ChainCount = $Results.Count
                TaskID     = $Results[0].TaskID
                EventCount = $Results[0].EventCount
                Events     = $Results[0].Events
            }
        }
        else {
            Write-Host "    ! No events found for $($Site.Name)" -ForegroundColor Yellow
            $TestResults += [PSCustomObject]@{
                Website    = $Site.Name
                Found      = $false
                ChainCount = 0
                TaskID     = $null
                EventCount = 0
                Events     = $null
            }
        }
    }
    catch {
        Write-Host "    ✗ Search failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
#endregion

#region Test 7: Error Analysis
Write-Host "`n[TEST 7] Analyze Certificate Errors" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

foreach ($Result in $TestResults | Where-Object { $_.Found }) {
    Write-Host "`n  Analyzing: $($Result.Website)" -ForegroundColor Cyan
    
    try {
        $ErrorAnalysis = Get-CapiErrorAnalysis -Events $Result.Events -IncludeSummary
        
        if ($ErrorAnalysis) {
            Write-Host "    ! Found $($ErrorAnalysis.Count) error(s)" -ForegroundColor Yellow
        }
        else {
            Write-Host "    ✓ No errors found - clean certificate chain" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    ✗ Analysis failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
#endregion

#region Test 8: Export Functionality
Write-Host "`n[TEST 8] Export Events to Multiple Formats" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

if (-not (Test-Path $ExportFolder)) {
    New-Item -Path $ExportFolder -ItemType Directory -Force | Out-Null
}

$ExportFormats = @('CSV', 'JSON', 'HTML', 'XML')

foreach ($Result in $TestResults | Where-Object { $_.Found } | Select-Object -First 1) {
    Write-Host "`n  Exporting events for: $($Result.Website)" -ForegroundColor Cyan
    
    foreach ($Format in $ExportFormats) {
        try {
            $Extension = $Format.ToLower()
            $FileName = "$($Result.Website.Replace('.', '_'))_$(Get-Date -Format 'yyyyMMdd_HHmmss').$Extension"
            $FilePath = Join-Path $ExportFolder $FileName
            
            Export-CapiEvents -Events $Result.Events -Path $FilePath -Format $Format -IncludeErrorAnalysis -TaskID $Result.TaskID
            
            if (Test-Path $FilePath) {
                $FileSize = [math]::Round((Get-Item $FilePath).Length / 1KB, 2)
                Write-Host "    ✓ $Format export successful ($FileSize KB)" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "    ✗ $Format export failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host "`n  Export folder: $ExportFolder" -ForegroundColor Gray
#endregion

#region Test 9: Helper Functions
Write-Host "`n[TEST 9] Test Helper Functions" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

try {
    # Test Get-CAPI2ErrorDetails
    Write-Host "`n  Testing Get-CAPI2ErrorDetails..." -ForegroundColor Cyan
    $ErrorDetail = Get-CAPI2ErrorDetails -ErrorCode "0x800B0101"
    
    if ($ErrorDetail.HexCode -eq "CERT_E_EXPIRED") {
        Write-Host "    ✓ Error code translation works correctly" -ForegroundColor Green
        Write-Host "      Code: $($ErrorDetail.Code)" -ForegroundColor Gray
        Write-Host "      Name: $($ErrorDetail.HexCode)" -ForegroundColor Gray
        Write-Host "      Severity: $($ErrorDetail.Severity)" -ForegroundColor Gray
    }
}
catch {
    Write-Host "    ✗ Helper function test failed: $($_.Exception.Message)" -ForegroundColor Red
}
#endregion

#region Test 10: Cleanup
Write-Host "`n[TEST 10] Cleanup" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

if (-not $KeepLogEnabled) {
    try {
        Disable-CAPI2EventLog
        Write-Host "  ✓ CAPI2 logging disabled" -ForegroundColor Green
    }
    catch {
        Write-Host "  ! Could not disable logging: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
else {
    Write-Host "  ! Keeping CAPI2 logging enabled (as requested)" -ForegroundColor Yellow
}
#endregion

#region Test Summary
Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                              ║" -ForegroundColor Cyan
Write-Host "║                       TEST SUMMARY                           ║" -ForegroundColor Cyan
Write-Host "║                                                              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nTest Results:" -ForegroundColor White
Write-Host "  Websites Tested: $($TestWebsites.Count)" -ForegroundColor Gray
Write-Host "  Events Found: $($TestResults | Where-Object {$_.Found} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Gray
Write-Host "  Total Events: $(($TestResults | Where-Object {$_.Found} | Measure-Object -Property EventCount -Sum).Sum)" -ForegroundColor Gray
Write-Host "  Exports Created: $(if (Test-Path $ExportFolder) {(Get-ChildItem $ExportFolder | Measure-Object).Count} else {0})" -ForegroundColor Gray

Write-Host "`nDetailed Results:" -ForegroundColor White
$TestResults | Format-Table Website, Found, ChainCount, EventCount -AutoSize

Write-Host "`nExported Files:" -ForegroundColor White
if (Test-Path $ExportFolder) {
    Get-ChildItem $ExportFolder | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
}

Write-Host "`n✓ Integration test complete!" -ForegroundColor Green
Write-Host "  Check exported files in: $ExportFolder`n" -ForegroundColor Gray
#endregion
