# CAPI2 Event Log Correlation Toolkit

[![Version](https://img.shields.io/badge/version-2.7-blue.svg)](https://github.com/BetaHydri/GetCapiCorrelationTask)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)
[![Author](https://img.shields.io/badge/author-Jan%20Tiedemann-orange.svg)](https://github.com/BetaHydri)

A powerful PowerShell toolkit for analyzing Windows CAPI2 (Cryptographic API) event logs, enabling administrators to troubleshoot certificate validation, TLS/SSL connection issues, and certificate chain building problems.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Command Reference](#-command-reference)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
  - [Event Log Management](#event-log-management)
  - [Search by DNS/Certificate Name](#search-by-dnscertificate-name)
  - [Error Analysis](#error-analysis)
  - [Export Functionality](#export-functionality)
  - [Comparison Features](#comparison-features)
- [Functions](#-functions)
- [Examples](#-examples)
- [Error Codes Reference](#-error-codes-reference)
- [Troubleshooting](#-troubleshooting)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)
- [Version History](#-version-history)
- [Acknowledgments](#-acknowledgments)
- [Support](#-support)

---

## 🔍 Overview

The CAPI2 Event Log Correlation Toolkit simplifies the complex task of analyzing certificate validation chains in Windows. When applications establish secure connections (TLS/SSL), Windows logs detailed cryptographic operations to the CAPI2 event log. These events are correlated using a TaskID (GUID), but finding the right correlation chain traditionally required manual searching.

**Version 2.7** introduces critical bug fixes for correlation chain retrieval and error detection, plus enhanced support for dual correlation mechanisms in modern CAPI2 events.

### What's New in v2.7

- 🔧 **Dual Correlation Support**: Now retrieves complete chains using BOTH chainRef and CorrelationAuxInfo TaskId
- 🐛 **Fixed Error Detection**: Corrected XML namespace handling for accurate error code extraction
- 📊 **Enhanced Event Retrieval**: Modern CAPI2 events now properly correlated (3-8 events per chain)
- 🎯 **Normalized Error Codes**: Automatic normalization of hex codes (800B0101 → 0x800B0101)

### What's New in v2.5

- 🔍 **Intelligent Error Analysis**: Automatic error code translation with human-readable descriptions
- 📊 **Comprehensive Error Tables**: See exactly what failed, why, and how to fix it
- 🎯 **Event Log Management**: Enable, disable, clear, and check status of CAPI2 logging
- 💾 **Export Functionality**: Export to CSV, JSON, HTML, or XML formats
- 🔄 **Comparison Features**: Compare before/after to verify error resolution
- 📖 **Error Code Dictionary**: Built-in reference for common CAPI2 error codes
- 🎨 **Enhanced Reporting**: Beautiful HTML reports with color-coded errors

---

## 🚀 Features

### Core Capabilities
- **Automatic Correlation Discovery**: Search by DNS name, certificate subject, or issuer
- **Complete Chain Retrieval**: Get all events in a certificate validation sequence
- **Smart Error Detection**: Automatically identifies and explains certificate errors
- **Multi-Format Export**: Export to CSV, JSON, HTML, or XML
- **Before/After Comparison**: Track error resolution progress

### Event Log Management
- **Enable/Disable Logging**: Control CAPI2 event collection
- **Clear Event Log**: Start fresh troubleshooting sessions with optional backup
- **Status Monitoring**: Check log status, event count, and date ranges

### Analysis Features
- **Error Translation**: Convert cryptic error codes to actionable information
- **Root Cause Analysis**: Understand why certificate validation failed
- **Resolution Guidance**: Get step-by-step fixes for common issues
- **Severity Levels**: Prioritize critical vs. warning issues

---

## 📖 Command Reference

The CAPI2Tools module provides 12 functions and 5 convenient aliases for certificate validation analysis and troubleshooting.

### Functions

| Command | Purpose |
|---------|---------|
| **`Get-CapiCertificateReport`** | **⭐ RECOMMENDED** - Simplified one-command solution: search, analyze, and export certificate errors in a single step. Perfect for quick diagnostics! |
| **`Find-CapiEventsByName`** | Search CAPI2 events by DNS name, certificate subject, or issuer. Returns complete correlation chains for matching certificates. |
| **`Get-CapiTaskIDEvents`** | Retrieve all events in a correlation chain using a TaskID (GUID). Use when you have a specific TaskID from event logs. |
| **`Get-CapiErrorAnalysis`** | Analyze events for errors and display comprehensive error tables with severity levels, descriptions, common causes, and resolution steps. |
| **`Export-CapiEvents`** | Export events to CSV, JSON, HTML, or XML format. HTML exports include error analysis and color-coded severity indicators. |
| **`Compare-CapiEvents`** | Compare two correlation chains (before/after) to identify resolved, new, or persistent errors. Useful for validating fixes. |
| **`Enable-CAPI2EventLog`** | Enable the CAPI2 Operational event log for certificate validation logging. Requires administrator privileges. |
| **`Disable-CAPI2EventLog`** | Disable CAPI2 logging to conserve system resources when troubleshooting is complete. Requires administrator privileges. |
| **`Clear-CAPI2EventLog`** | Clear all CAPI2 events with optional backup. Use to start fresh troubleshooting sessions. Requires administrator privileges. |
| **`Get-CAPI2EventLogStatus`** | Display current log status: enabled state, event count, size, oldest/newest event timestamps, and file path. |
| **`Start-CAPI2Troubleshooting`** | Interactive troubleshooting session that enables logging, clears events, waits for issue reproduction, then analyzes results. |
| **`Stop-CAPI2Troubleshooting`** | Complete troubleshooting by exporting events, disabling logging, and cleaning up. Pairs with `Start-CAPI2Troubleshooting`. |

### Aliases

Convenient shortcuts for commonly used commands:

| Alias | Target Function | Purpose |
|-------|----------------|---------|
| **`Find-CertEvents`** | `Find-CapiEventsByName` | Shorter name for quick certificate event searches |
| **`Get-CertChain`** | `Get-CapiTaskIDEvents` | Intuitive name for retrieving certificate chain events |
| **`Enable-CapiLog`** | `Enable-CAPI2EventLog` | Quick enable with shorter typing |
| **`Disable-CapiLog`** | `Disable-CAPI2EventLog` | Quick disable with shorter typing |
| **`Clear-CapiLog`** | `Clear-CAPI2EventLog` | Quick clear with shorter typing |

### Quick Reference Examples

```powershell
# ⭐ SIMPLEST: One command to do everything
Get-CapiCertificateReport -Name "problematic-site.com" -ExportPath "report.html"

# Search for events (function or alias)
Find-CapiEventsByName -Name "microsoft.com"
Find-CertEvents -Name "microsoft.com"              # Same using alias

# Get specific correlation chain
Get-CapiTaskIDEvents -TaskID "12345678-1234-1234-1234-123456789abc"
Get-CertChain -TaskID "12345678-1234-1234-1234-123456789abc"  # Same using alias

# Manage event log
Enable-CAPI2EventLog    # or Enable-CapiLog
Disable-CAPI2EventLog   # or Disable-CapiLog
Clear-CAPI2EventLog     # or Clear-CapiLog

# Check log status
Get-CAPI2EventLogStatus

# Analyze and export
$Events = Find-CertEvents -Name "example.com"
Get-CapiErrorAnalysis -Events $Events[0].Events
Export-CapiEvents -Events $Events[0].Events -Path "report.html" -Format HTML
```

---

## 💻 Requirements

- **Operating System**: Windows 7/Server 2008 R2 or later
- **PowerShell**: Version 5.1 or higher (PowerShell Core 7+ supported)
- **Permissions**: Read access to `Microsoft-Windows-CAPI2/Operational` event log
- **CAPI2 Logging**: Must be enabled (see [Troubleshooting](#troubleshooting))

---

## 📥 Installation

### Option 1: Module Installation (Recommended)

```powershell
# Copy module to user module directory
$ModulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\CAPI2Tools"
New-Item -Path $ModulePath -ItemType Directory -Force
Copy-Item .\CAPI2Tools.psm1 -Destination $ModulePath

# Import module
Import-Module CAPI2Tools

# Verify installation
Get-Module CAPI2Tools
Get-Command -Module CAPI2Tools
```

### Option 2: Clone Repository

```powershell
git clone https://github.com/BetaHydri/GetCapiCorrelationTask.git
cd GetCapiCorrelationTask
Import-Module .\CAPI2Tools.psm1

# Or for temporary session import
Import-Module .\CAPI2Tools.psm1 -Force
```

### Option 3: Direct Import (Temporary Session)

```powershell
# Import module directly without installation
Import-Module "C:\Path\To\CAPI2Tools.psm1"
```

### Persistent Import (Add to PowerShell Profile)

```powershell
# Add to your PowerShell profile for automatic loading
Add-Content $PROFILE "`nImport-Module CAPI2Tools"
```

---

## ⚡ Quick Start

### Simplest Workflow (Recommended for Most Users)

The **easiest way** to diagnose certificate issues - one command does it all:

```powershell
# Just search and view results
Get-CapiCertificateReport -Name "problematic-site.com"

# Search and export to HTML in one command
Get-CapiCertificateReport -Name "problematic-site.com" -ExportPath "report.html"

# Search, export, and open report automatically
Get-CapiCertificateReport -Name "*.contoso.com" -ExportPath "report.html" -OpenReport
```

**That's it!** This single command:
- ✅ Searches for certificate events
- ✅ Analyzes all errors automatically
- ✅ Exports to HTML/JSON/CSV/XML
- ✅ Shows clear, actionable results

### Advanced Workflow (For Power Users)

For complex scenarios requiring manual control:

```powershell
# 1. Enable CAPI2 logging
Enable-CAPI2EventLog

# 2. Clear existing events for clean test
Clear-CAPI2EventLog

# 3. Reproduce the certificate issue (browse to website, run application, etc.)

# 4. Search for events by domain name
$Results = Find-CapiEventsByName -Name "yoursite.com"

# 5. Analyze errors with detailed explanations
Get-CapiErrorAnalysis -Events $Results[0].Events -IncludeSummary

# 6. Export for documentation
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports\cert_issue.html" -IncludeErrorAnalysis

# 7. After fixing the issue, compare results
$After = Find-CapiEventsByName -Name "yoursite.com"
Compare-CapiEvents -ReferenceEvents $Results[0].Events -DifferenceEvents $After[0].Events

# 8. Disable logging when done
Disable-CAPI2EventLog
```

**Note**: The simplified `Get-CapiCertificateReport` function handles steps 4-6 automatically!

---

## 📖 Usage

### Event Log Management

Control CAPI2 event logging for troubleshooting:

```powershell
# Check current status
Get-CAPI2EventLogStatus

# Enable logging (requires admin)
Enable-CAPI2EventLog

# Disable logging
Disable-CAPI2EventLog

# Clear log (with optional backup)
Clear-CAPI2EventLog -Backup "C:\Backup\CAPI2_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
```

**Output Example:**
```
=== CAPI2 Event Log Status ===
Status:          ENABLED
Event Count:     847
Max Size:        20 MB
Oldest Event:    12/08/2025 14:23:11
Newest Event:    12/09/2025 09:45:32
Log Location:    %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-CAPI2%4Operational.evtx
```

---

### Search by DNS/Certificate Name

The primary function for finding certificate chains:

```powershell
# Search for a specific domain
Find-CapiEventsByName -Name "microsoft.com"

# Search with wildcards
Find-CapiEventsByName -Name "*.contoso.com"

# Search in the last 48 hours
Find-CapiEventsByName -Name "google.com" -Hours 48

# Search for certificate issuer
Find-CapiEventsByName -Name "DigiCert"
```

---

### Error Analysis

Get comprehensive error analysis with resolution steps:

```powershell
# Analyze errors from search results
$Results = Find-CapiEventsByName -Name "failingsite.com"
Get-CapiErrorAnalysis -Events $Results[0].Events

# Include error summary
Get-CapiErrorAnalysis -Events $Results[0].Events -IncludeSummary

# Direct TaskID analysis
$Events = Get-CapiTaskIDEvents -TaskID "GUID-HERE"
Get-CapiErrorAnalysis -Events $Events
```

**Output Example:**
```
=== CAPI2 Error Analysis ===
Found 2 error(s) in the certificate validation chain.

TimeCreated          Severity ErrorName                Certificate      Description
-----------          -------- ---------                -----------      -----------
12/9/2025 9:45:32 AM Critical  CRYPT_E_REVOCATION_...  mail.contoso.com The revocation...

=== Detailed Error Information ===

[Critical] CRYPT_E_REVOCATION_OFFLINE - 0x80092013
  Certificate:   mail.contoso.com
  Issuer:        DigiCert TLS RSA SHA256 2020 CA1
  Description:   The revocation function was unable to check revocation because the revocation server was offline.
  Common Cause:  Network connectivity issue, CRL/OCSP server unavailable, firewall blocking
  Resolution:    Check network connectivity, verify CRL/OCSP URLs are accessible, check proxy settings
```

---

### Export Functionality

Export events to multiple formats:

```powershell
# Export to CSV
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports\events.csv"

# Export to JSON with error analysis
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports\analysis.json" -IncludeErrorAnalysis

# Export to HTML report (recommended for documentation)
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports\cert_report.html" -IncludeErrorAnalysis -TaskID $Results[0].TaskID

# Export to XML
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports\events.xml"
```

The HTML export creates a beautiful, color-coded report with:
- Event summary and metadata
- Error analysis table with severity indicators
- Full event details with certificates
- Timestamps and process information

---

### Comparison Features

Compare certificate validation before and after fixes:

```powershell
# Capture baseline (before fix)
$Before = Find-CapiEventsByName -Name "problemsite.com"

# Apply your fix (install certificate, update configuration, etc.)

# Capture after fix
$After = Find-CapiEventsByName -Name "problemsite.com"

# Compare to see what changed
Compare-CapiEvents -ReferenceEvents $Before[0].Events -DifferenceEvents $After[0].Events

# Custom labels for clarity
Compare-CapiEvents -ReferenceEvents $Before[0].Events -DifferenceEvents $After[0].Events `
    -ReferenceLabel "Before Certificate Update" -DifferenceLabel "After Certificate Update"
```

**Output Example:**
```
=== CAPI2 Event Comparison ===
Before Events: 12 | After Events: 10

=== Comparison Results ===
✓ ERRORS RESOLVED!
  Before had 2 error(s), After has 0 errors.

Resolved Errors:
ErrorName                    Certificate       Description
---------                    -----------       -----------
CRYPT_E_REVOCATION_OFFLINE  mail.contoso.com  The revocation function was unable...

=== Summary ===
Resolved: 2 | New: 0 | Persistent: 0

✓ Overall improvement: Error count reduced from 2 to 0
```

---

## 🔧 Functions

### Core Search Functions

#### `Find-CapiEventsByName`
Searches CAPI2 events by DNS name or certificate subject and retrieves all correlated events.

**Parameters**:
- `Name` (Required): DNS name or certificate subject to search for
- `MaxEvents`: Maximum events to retrieve (default: 1000)
- `Hours`: Hours to look back (default: 24)
- `IncludePattern`: Additional filter pattern

**Returns**: Array of correlation chain objects

---

#### `Get-CapiTaskIDEvents`
Retrieves all CAPI2 events that share the same correlation TaskID.

**Parameters**:
- `TaskID` (Required): Correlation TaskID (GUID)

**Returns**: Array of event objects

---

### Analysis Functions

#### `Get-CapiErrorAnalysis`
Analyzes CAPI2 events and presents errors in a comprehensive table format with descriptions and resolutions.

**Parameters**:
- `Events` (Required): Array of CAPI2 events
- `IncludeSummary`: Shows error count summary

**Returns**: Error analysis table with severity, descriptions, and resolution steps

---

### Export Functions

#### `Export-CapiEvents`
Exports CAPI2 events to various formats (CSV, JSON, HTML, XML).

**Parameters**:
- `Events` (Required): Array of CAPI2 events to export
- `Path` (Required): Output file path
- `Format`: CSV, JSON, HTML, or XML (auto-detected from extension)
- `IncludeErrorAnalysis`: Include error analysis in export
- `TaskID`: TaskID for reference in export

---

### Comparison Functions

#### `Compare-CapiEvents`
Compares two CAPI2 event correlation chains to identify changes or resolved errors.

**Parameters**:
- `ReferenceEvents` (Required): Original/baseline events
- `DifferenceEvents` (Required): New events to compare
- `ReferenceLabel`: Label for reference (default: "Before")
- `DifferenceLabel`: Label for difference (default: "After")

**Returns**: Comparison summary with resolved, new, and persistent errors

---

### Event Log Management Functions

#### `Enable-CAPI2EventLog`
Enables the CAPI2 Operational event log. Requires administrative privileges.

---

#### `Disable-CAPI2EventLog`
Disables the CAPI2 Operational event log. Requires administrative privileges.

---

#### `Clear-CAPI2EventLog`
Clears all events from the CAPI2 log with optional backup. Requires administrative privileges.

**Parameters**:
- `Backup`: Path to backup file before clearing

---

#### `Get-CAPI2EventLogStatus`
Displays current status of the CAPI2 event log including enabled state, event count, and date ranges.

---

### Helper Functions

#### `Convert-EventLogRecord`
Internal helper that converts Windows Event Log records to PowerShell objects.

---

#### `Format-XML`
Internal helper that formats XML data for readable output.

---

#### `Get-CAPI2ErrorDetails`
Internal helper that translates error codes to human-readable descriptions.

---

## 📚 Examples

### Example 1: Quick Certificate Diagnosis (Recommended)

```powershell
# ⭐ The easiest way - one command does everything!
Get-CapiCertificateReport -Name "expired.badssl.com" -ExportPath "report.html"

# With automatic browser opening
Get-CapiCertificateReport -Name "self-signed.badssl.com" -ExportPath "report.html" -OpenReport

# Export to JSON for automation
Get-CapiCertificateReport -Name "wrong.host.badssl.com" -ExportPath "errors.json"

# Search last 2 hours with detailed output
Get-CapiCertificateReport -Name "problematic-site.com" -Hours 2 -ShowDetails
```

**Before this simplified function, you had to write:**
```powershell
$Results = Find-CapiEventsByName -Name "expired.badssl.com"
Get-CapiErrorAnalysis -Events $Results[0].Events -IncludeSummary
Export-CapiEvents -Events $Results[0].Events -Path "report.html" -Format HTML -IncludeErrorAnalysis -TaskID $Results[0].TaskID
```

**Now just one line:**
```powershell
Get-CapiCertificateReport -Name "expired.badssl.com" -ExportPath "report.html"
```

### Example 2: Traditional Complete Troubleshooting Session (Advanced)

```powershell
# Start fresh troubleshooting session
Enable-CAPI2EventLog
Clear-CAPI2EventLog

# Reproduce the issue (browse to failing site, etc.)

# Find and analyze events
$Results = Find-CapiEventsByName -Name "problematic-site.com"
Get-CapiErrorAnalysis -Events $Results[0].Events -IncludeSummary

# Export for documentation
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports\issue_report.html" -IncludeErrorAnalysis
```

### Example 4: Track Fix Progress (Advanced)

```powershell
# Capture baseline
$Before = Find-CapiEventsByName -Name "myapp.company.com"

# Apply certificate fix

# Test again
$After = Find-CapiEventsByName -Name "myapp.company.com"

# Compare results
Compare-CapiEvents -ReferenceEvents $Before[0].Events -DifferenceEvents $After[0].Events
```

### Example 5: Investigate Specific Error (Advanced)

```powershell
# Find events with revocation errors
$Results = Find-CapiEventsByName -Name "*.microsoft.com" -IncludePattern "revocation"

# Analyze first chain
$Analysis = Get-CapiErrorAnalysis -Events $Results[0].Events

# Filter for critical errors only
$CriticalErrors = $Analysis | Where-Object { $_.Severity -eq "Critical" }
$CriticalErrors | Format-Table ErrorName, Certificate, Resolution -Wrap
```

### Example 6: Bulk Analysis and Reporting

```powershell
# ⭐ Simplified approach
$Sites = @("site1.com", "site2.com", "site3.com")
foreach ($Site in $Sites) {
    Get-CapiCertificateReport -Name $Site -ExportPath "C:\Reports\$($Site)_report.html" -Hours 168
}

# Advanced approach with more control
$Sites = @("site1.com", "site2.com", "site3.com")
foreach ($Site in $Sites) {
    $Results = Find-CapiEventsByName -Name $Site -Hours 168
    
    if ($Results) {
        $OutputPath = "C:\Reports\$($Site)_analysis.html"
        Export-CapiEvents -Events $Results[0].Events -Path $OutputPath -IncludeErrorAnalysis
        Write-Host "✓ Exported $Site analysis to $OutputPath" -ForegroundColor Green
    }
}
```

### Example 7: Monitor Application Certificate Usage

```powershell
# Enable logging
Enable-CAPI2EventLog

# Run your application
Start-Process "C:\Apps\MyApp.exe"
Start-Sleep -Seconds 30

# Find all certificate operations
$Results = Find-CapiEventsByName -Name "*" -Hours 1

# Filter by application process
$AppEvents = $Results | ForEach-Object {
    $_.Events | Where-Object { $_.DetailedMessage -like "*MyApp.exe*" }
}

Get-CapiErrorAnalysis -Events $AppEvents
```

---

## 🔐 Error Codes Reference

Common CAPI2 error codes with explanations:

| Error Code | Name | Description | Common Resolution |
|------------|------|-------------|-------------------|
| `0x80092013` | CRYPT_E_REVOCATION_OFFLINE | Revocation server offline | Check network/firewall, verify CRL/OCSP URLs |
| `0x80092012` | CRYPT_E_REVOKED | Certificate revoked | Obtain new certificate, investigate revocation |
| `0x800B0101` | CERT_E_EXPIRED | Certificate expired | Renew certificate, check system time |
| `0x800B010F` | CERT_E_CN_NO_MATCH | Common name mismatch | Get certificate with correct CN/SAN |
| `0x800B0109` | CERT_E_UNTRUSTEDROOT | Untrusted root CA | Install root CA certificate |
| `0x800B010A` | CERT_E_CHAINING | Cannot build chain | Install intermediate certificates |
| `0x80096004` | TRUST_E_CERT_SIGNATURE | Invalid signature | Re-download certificate, verify source |
| `0x800B0111` | CERT_E_WRONG_USAGE | Wrong certificate usage | Get certificate with correct EKU |
| `0x80092010` | CRYPT_E_NOT_FOUND | Object not found | Verify certificate installation |

**For detailed error analysis**, use `Get-CapiErrorAnalysis` which provides:
- Full error description
- Common causes
- Step-by-step resolution instructions
- Severity classification

---

## 🔍 Troubleshooting

### CAPI2 Logging Not Enabled

If you see no events, CAPI2 logging may be disabled:

```powershell
# Enable CAPI2 logging
wevtutil.exe sl Microsoft-Windows-CAPI2/Operational /e:true

# Verify it's enabled
wevtutil.exe gl Microsoft-Windows-CAPI2/Operational
```

### No Events Found

If searches return no results:

1. **Increase time range**: `Find-CapiEventsByName -Name "example.com" -Hours 168`
2. **Broaden search**: Use wildcards like `*.example.com`
3. **Check event log**: Verify events exist: `Get-WinEvent -LogName Microsoft-Windows-CAPI2/Operational -MaxEvents 10`
4. **Verify logging**: Ensure CAPI2 logging is enabled (see above)

### Performance Issues

For large event logs:

```powershell
# Limit initial retrieval
Find-CapiEventsByName -Name "example.com" -MaxEvents 500 -Hours 6

# Or use TaskID directly if known
Get-CapiTaskIDEvents -TaskID "KNOWN-GUID-HERE"
```

### Access Denied

Run PowerShell as Administrator if you encounter permission errors.

---

## 🧪 Testing

The module includes two complementary test suites for quality assurance:

### Quick Unit Tests (Pester)
Fast automated tests with mock data - **no admin required**:

```powershell
# Run all unit tests (~1.5 seconds)
Invoke-Pester -Path .\Tests\CAPI2Tools.Tests.ps1

# Run with detailed output
Invoke-Pester -Path .\Tests\CAPI2Tools.Tests.ps1 -PassThru

# Exclude integration tests
Invoke-Pester -Path .\Tests\CAPI2Tools.Tests.ps1 -ExcludeTag Integration
```

**Coverage**: 29 tests covering module structure, error codes, exports, and core functionality

### Integration/E2E Tests
Comprehensive real-world testing with live websites and event log - **requires admin**:

```powershell
# Run full integration test suite
.\Test-CAPI2Module.ps1

# Keep CAPI2 logging enabled after tests
.\Test-CAPI2Module.ps1 -KeepLogEnabled

# Custom export folder
.\Test-CAPI2Module.ps1 -ExportFolder "C:\MyTests"
```

**Coverage**: 10 integration tests including live certificate validation, event capture, and export workflows

### When to Use Which?

| Scenario | Pester Unit Tests | Integration Tests |
|----------|------------------|-------------------|
| During development | ✅ Yes | ❌ No |
| Before commits | ✅ Yes | ⚠️ Optional |
| CI/CD pipeline | ✅ Yes | ❌ No (requires admin) |
| Before releases | ✅ Yes | ✅ Yes |
| Troubleshooting | ❌ No | ✅ Yes |
| Demonstrations | ❌ No | ✅ Yes |

📖 See [Tests/README.md](Tests/README.md) for detailed Pester test documentation.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Guidelines

1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commit messages
4. Test thoroughly on Windows 10/11 and Server 2019/2022
5. Submit a pull request

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0**.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.en.html) for details.

---

## 👤 Author

**Jan Tiedemann**

- GitHub: [@BetaHydri](https://github.com/BetaHydri)
- Repository: [GetCapiCorrelationTask](https://github.com/BetaHydri/GetCapiCorrelationTask)

---

## 📊 Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.7 | December 2025 | Fixed correlation chain retrieval with dual mechanism support (chainRef + CorrelationAuxInfo TaskId), fixed error detection XML namespace issues, normalized hex error code handling, enhanced modern CAPI2 event support |
| 2.6 | December 2025 | Added `Get-CapiCertificateReport` simplified one-command workflow function, improved parameter documentation for ExportPath (now clearly requires filename with extension), enhanced user experience |
| 2.5 | December 2025 | Added error analysis tables, CAPI2 log management, export functionality (CSV/JSON/HTML/XML), comparison features, error code dictionary |
| 2.0 | December 2025 | Added DNS/certificate name search, enhanced UI, improved documentation |
| 1.0 | 2022 | Initial release with TaskID-based correlation |

---

## 🙏 Acknowledgments

- Microsoft CAPI2 documentation team
- PowerShell community for best practices
- Contributors and users providing feedback

---

## 📞 Support

For issues, questions, or suggestions:

- Open an issue on [GitHub](https://github.com/BetaHydri/GetCapiCorrelationTask/issues)
- Check existing documentation and examples
- Review PowerShell event log fundamentals

---

**Made with ❤️ for Windows Administrators**
     
