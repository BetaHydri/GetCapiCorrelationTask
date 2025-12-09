<#
.SYNOPSIS
    Unified test runner for CAPI2Tools - runs both Pester unit tests and integration tests
    
.DESCRIPTION
    Convenience script to run all tests (unit + integration) or choose specific test suites.
    
    This script provides a simple interface to:
    - Run fast Pester unit tests (no admin, ~1.5 seconds)
    - Run comprehensive integration tests (requires admin, live websites)
    - Run both sequentially with clear reporting
    
.PARAMETER TestType
    Type of tests to run:
    - 'All' (default): Runs both unit and integration tests
    - 'Unit': Only Pester unit tests
    - 'Integration': Only integration/E2E tests
    
.PARAMETER SkipIntegration
    Skip integration tests (runs only Pester unit tests)
    
.PARAMETER IntegrationOnly
    Run only integration tests (skips Pester unit tests)
    
.EXAMPLE
    .\Run-AllTests.ps1
    Runs both unit and integration tests
    
.EXAMPLE
    .\Run-AllTests.ps1 -TestType Unit
    Runs only fast Pester unit tests
    
.EXAMPLE
    .\Run-AllTests.ps1 -SkipIntegration
    Runs only unit tests (same as -TestType Unit)
    
.EXAMPLE
    .\Run-AllTests.ps1 -TestType Integration
    Runs only integration tests (requires admin)
    
.NOTES
    Author: Jan Tiedemann
    Date: December 2025
    
    Unit Tests:
    - Fast execution (~1.5 seconds)
    - No admin required
    - No live data needed
    - Perfect for CI/CD
    
    Integration Tests:
    - Comprehensive validation (~30-60 seconds)
    - Requires admin privileges
    - Tests with live websites and event log
    - Best for pre-release validation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'Unit', 'Integration')]
    [string]$TestType = 'All',
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipIntegration,
    
    [Parameter(Mandatory = $false)]
    [switch]$IntegrationOnly
)

# Determine what to run
if ($SkipIntegration) {
    $TestType = 'Unit'
}
elseif ($IntegrationOnly) {
    $TestType = 'Integration'
}

# Script paths
$ScriptRoot = $PSScriptRoot
$PesterTestPath = Join-Path $ScriptRoot "Tests\CAPI2Tools.Tests.ps1"
$IntegrationTestPath = Join-Path $ScriptRoot "Test-CAPI2Module.ps1"

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                              ║" -ForegroundColor Cyan
Write-Host "║              CAPI2Tools - Unified Test Runner                ║" -ForegroundColor Cyan
Write-Host "║                                                              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Track overall results
$UnitTestsPassed = $null
$IntegrationTestsPassed = $null
$StartTime = Get-Date

#region Unit Tests (Pester)
if ($TestType -eq 'All' -or $TestType -eq 'Unit') {
    Write-Host "`n[UNIT TESTS] Running Pester Unit Tests..." -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
    Write-Host "Type: Fast automated tests with mock data" -ForegroundColor Gray
    Write-Host "Requirements: None (no admin, no live data)" -ForegroundColor Gray
    Write-Host "Duration: ~1.5 seconds`n" -ForegroundColor Gray
    
    if (-not (Test-Path $PesterTestPath)) {
        Write-Host "✗ Pester tests not found at: $PesterTestPath" -ForegroundColor Red
        $UnitTestsPassed = $false
    }
    else {
        try {
            # Check if Pester is available
            if (-not (Get-Module -ListAvailable -Name Pester)) {
                Write-Warning "Pester module not installed. Installing..."
                Install-Module -Name Pester -Force -SkipPublisherCheck -Scope CurrentUser
            }
            
            # Run Pester tests
            $PesterResult = Invoke-Pester -Path $PesterTestPath -PassThru
            
            if ($PesterResult.FailedCount -eq 0) {
                Write-Host "`n✓ All unit tests passed! ($($PesterResult.PassedCount)/$($PesterResult.TotalCount))" -ForegroundColor Green
                $UnitTestsPassed = $true
            }
            else {
                Write-Host "`n✗ Some unit tests failed: $($PesterResult.FailedCount)/$($PesterResult.TotalCount)" -ForegroundColor Red
                $UnitTestsPassed = $false
            }
            
            Write-Host "Execution time: $($PesterResult.Time.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Gray
        }
        catch {
            Write-Host "`n✗ Unit tests failed with error: $($_.Exception.Message)" -ForegroundColor Red
            $UnitTestsPassed = $false
        }
    }
}
#endregion

#region Integration Tests
if ($TestType -eq 'All' -or $TestType -eq 'Integration') {
    Write-Host "`n`n[INTEGRATION TESTS] Running Integration/E2E Tests..." -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
    Write-Host "Type: Comprehensive real-world validation" -ForegroundColor Gray
    Write-Host "Requirements: Admin privileges, Internet access" -ForegroundColor Gray
    Write-Host "Duration: ~30-60 seconds`n" -ForegroundColor Gray
    
    # Check admin privileges
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsAdmin) {
        Write-Host "✗ Integration tests require administrator privileges" -ForegroundColor Red
        Write-Host "  Please run PowerShell as Administrator and try again" -ForegroundColor Yellow
        $IntegrationTestsPassed = $false
    }
    elseif (-not (Test-Path $IntegrationTestPath)) {
        Write-Host "✗ Integration test script not found at: $IntegrationTestPath" -ForegroundColor Red
        $IntegrationTestsPassed = $false
    }
    else {
        try {
            # Run integration tests
            & $IntegrationTestPath -ErrorAction Stop
            
            # Check if it completed successfully (assumes script exits with code 0 on success)
            if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) {
                Write-Host "`n✓ Integration tests completed successfully!" -ForegroundColor Green
                $IntegrationTestsPassed = $true
            }
            else {
                Write-Host "`n✗ Integration tests failed (exit code: $LASTEXITCODE)" -ForegroundColor Red
                $IntegrationTestsPassed = $false
            }
        }
        catch {
            Write-Host "`n✗ Integration tests failed with error: $($_.Exception.Message)" -ForegroundColor Red
            $IntegrationTestsPassed = $false
        }
    }
}
#endregion

#region Summary
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

Write-Host "`n`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                              ║" -ForegroundColor Cyan
Write-Host "║                       TEST SUMMARY                           ║" -ForegroundColor Cyan
Write-Host "║                                                              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nTest Results:" -ForegroundColor White

if ($TestType -eq 'All' -or $TestType -eq 'Unit') {
    if ($UnitTestsPassed) {
        Write-Host "  ✓ Unit Tests: PASSED" -ForegroundColor Green
    }
    elseif ($null -ne $UnitTestsPassed) {
        Write-Host "  ✗ Unit Tests: FAILED" -ForegroundColor Red
    }
}

if ($TestType -eq 'All' -or $TestType -eq 'Integration') {
    if ($IntegrationTestsPassed) {
        Write-Host "  ✓ Integration Tests: PASSED" -ForegroundColor Green
    }
    elseif ($null -ne $IntegrationTestsPassed) {
        Write-Host "  ✗ Integration Tests: FAILED" -ForegroundColor Red
    }
}

Write-Host "`nTotal Execution Time: $($Duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Gray

# Overall status
$OverallSuccess = $true
if ($null -ne $UnitTestsPassed -and -not $UnitTestsPassed) { $OverallSuccess = $false }
if ($null -ne $IntegrationTestsPassed -and -not $IntegrationTestsPassed) { $OverallSuccess = $false }

if ($OverallSuccess) {
    Write-Host "`n✓✓✓ ALL TESTS PASSED ✓✓✓" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "`n✗✗✗ SOME TESTS FAILED ✗✗✗" -ForegroundColor Red
    Write-Host "Review the output above for details`n" -ForegroundColor Yellow
    exit 1
}
#endregion
