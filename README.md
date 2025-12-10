# CAPI2 Event Log Correlation Toolkit

[![Version](https://img.shields.io/badge/version-2.10.1-blue.svg)](https://github.com/BetaHydri/GetCapiCorrelationTask)
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

**Version 2.10.1** adds support for Event ID 82 (catalog lookup failures) in error analysis.

### What's New in v2.10.1

- 📦 **Event ID 82 Support**: Catalog lookup failures now included in error analysis (CryptCATAdminEnumCatalogFromHash)
- 🔍 **Error Code 490**: Added ERROR_NOT_FOUND (0x000001EA) for catalog security information not found
- ℹ️ **Informational Severity**: Catalog lookups marked as Info (not critical errors) since many legitimate files aren't cataloged
- 🔗 **Complete Correlation Chains**: Event ID 82 now visible in TaskID-based correlation analysis
- 📚 **12 New Error Codes**: Expanded coverage with CERT_E_PURPOSE, SEC_E_WRONG_PRINCIPAL, TRUST_E_BAD_DIGEST, and 9 more common errors
- 🏢 **Enterprise Support**: Better diagnostics for Group Policy restrictions, TLS inspection, and mutual authentication
- 🔐 **Certificate Thumbprints**: Error analysis now extracts and displays certificate thumbprints for easy identification
- 🎯 **FilterType Parameter**: New `-FilterType` with tab completion for common scenarios (Revocation, Expired, Untrusted, etc.)

### What's New in v2.10

- 🔐 **TrustStatus Parsing**: Extracts and analyzes ErrorStatus and InfoStatus flags from certificate chain validation
- 📊 **23 Error Flags Mapped**: CERT_TRUST_IS_NOT_TIME_VALID, CERT_TRUST_IS_REVOKED, CERT_TRUST_HAS_WEAK_SIGNATURE, etc.
- ℹ️ **13 Info Flags**: Issuer matching, self-signed detection, preferred issuer identification
- ⚠️ **Enhanced Error Analysis**: `Get-CapiErrorAnalysis` now shows exactly which trust checks failed
- 📋 **Detailed HTML Reports**: Trust chain errors and info displayed with severity indicators
- 🎯 **Automatic Severity Tracking**: Critical/Error/Warning classification from trust validation flags
- 📦 **All Export Formats**: TrustStatus included in HTML, JSON, CSV, and XML exports

### What's New in v2.9

- 📁 **Multi-File Export**: Each correlation chain exports to a separate file (no more overwrites!)
- 🎯 **Smart File Naming**: Auto-generated filenames based on certificate name and TaskID (e.g., `microsoft.com_621E9428.html`)
- 📂 **Directory-Based Export**: Specify output directory instead of full file path
- ✅ **Format Validation**: New `-Format` parameter with ValidateSet (HTML, JSON, CSV, XML)
- 🔧 **Simplified Workflow**: `Get-CapiCertificateReport -Name "*.microsoft.com" -ExportPath "C:\Reports"`

### What's New in v2.8

- 🔍 **Enhanced Multi-Field Search**: Automatically searches SubjectAltName, CN, ProcessName, and certificate attributes
- 🎯 **Process-Based Correlation**: Find certificate validations by process name (chrome.exe, outlook.exe, etc.)
- 📊 **Simplified Usage**: `Get-CapiCertificateReport -Name` now searches all relevant fields automatically
- ⚡ **Priority-Based Matching**: Intelligent search order for faster, more accurate results

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
Get-CapiCertificateReport -Name "problematic-site.com" -ExportPath "C:\Reports"

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
Export-CapiEvents -Events $Events[0].Events -Path "C:\Reports" -Format HTML -IncludeErrorAnalysis -TaskID $Events[0].TaskID
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

# Search and export to HTML (default - best for human reading)
Get-CapiCertificateReport -Name "problematic-site.com" -ExportPath "C:\Reports"

# Search, export, and open report automatically in browser
Get-CapiCertificateReport -Name "*.contoso.com" -ExportPath "C:\Reports" -OpenReport

# Export to JSON for automation/integration with monitoring tools
Get-CapiCertificateReport -Name "api.company.com" -ExportPath "C:\Reports" -Format JSON

# Export to CSV for Excel analysis or bulk processing
Get-CapiCertificateReport -Name "*.internal.net" -ExportPath "C:\Reports" -Format CSV

# Export to XML for PowerShell pipeline processing
Get-CapiCertificateReport -Name "services.*" -ExportPath "C:\Reports" -Format XML
```

**Choose the right format for your needs:**
- 📄 **HTML** (default) - Beautiful reports for manual review, includes color coding and detailed error analysis
- 🔧 **JSON** - Machine-readable format for automation, monitoring systems (Splunk, ELK), or API integration
- 📊 **CSV** - Open in Excel for sorting, filtering, pivot tables, or importing into databases
- 📦 **XML** - Native PowerShell format, perfect for pipeline processing with `Import-Clixml` and automation scripts

**That's it!** This single command:
- ✅ Searches for certificate events
- ✅ Analyzes all errors automatically
- ✅ Exports to your chosen format
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
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports" -Format HTML -IncludeErrorAnalysis -TaskID $Results[0].TaskID

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

# ⭐ NEW: Use FilterType for common scenarios with autocomplete
Find-CapiEventsByName -Name "*.microsoft.com" -FilterType Revocation
Find-CapiEventsByName -Name "expired.badssl.com" -FilterType Expired
Find-CapiEventsByName -Name "self-signed.badssl.com" -FilterType Untrusted

# Custom pattern filtering (advanced)
Find-CapiEventsByName -Name "site.com" -IncludePattern "OCSP"
```

**Available FilterType options:**
- `Revocation` - Events related to revocation checking (OCSP, CRL)
- `Expired` - Certificate expiration issues
- `Untrusted` - Trust chain and root certificate issues
- `ChainBuilding` - Certificate chain construction events
- `PolicyValidation` - Certificate policy validation events
- `SignatureValidation` - Certificate signature verification
- `ErrorsOnly` - Events containing Result errors

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
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports" -Format CSV -TaskID $Results[0].TaskID

# Export to JSON with error analysis
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports" -Format JSON -IncludeErrorAnalysis -TaskID $Results[0].TaskID

# Export to HTML report (recommended for documentation)
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports" -Format HTML -IncludeErrorAnalysis -TaskID $Results[0].TaskID

# Export to XML
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports" -Format XML -TaskID $Results[0].TaskID
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
Get-CapiCertificateReport -Name "expired.badssl.com" -ExportPath "C:\Reports"

# With automatic browser opening
Get-CapiCertificateReport -Name "self-signed.badssl.com" -ExportPath "C:\Reports" -OpenReport

# Export to JSON for automation
Get-CapiCertificateReport -Name "wrong.host.badssl.com" -ExportPath "C:\Reports"

# Search last 2 hours with detailed output
Get-CapiCertificateReport -Name "problematic-site.com" -Hours 2 -ShowDetails
```

**Before this simplified function, you had to write:**
```powershell
$Results = Find-CapiEventsByName -Name "expired.badssl.com"
Get-CapiErrorAnalysis -Events $Results[0].Events -IncludeSummary
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports" -Format HTML -IncludeErrorAnalysis -TaskID $Results[0].TaskID
```

**Now just one line:**
```powershell
Get-CapiCertificateReport -Name "expired.badssl.com" -ExportPath "C:\Reports"
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
Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports" -Format HTML -IncludeErrorAnalysis -TaskID $Results[0].TaskID
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

### Example 5: Investigate Specific Error Types with FilterType

FilterType provides intuitive filtering with tab completion for common scenarios:

#### **Revocation Issues**
```powershell
# Find revocation check failures (CRL/OCSP)
$Results = Find-CapiEventsByName -Name "*.microsoft.com" -FilterType Revocation
$Analysis = Get-CapiErrorAnalysis -Events $Results[0].Events

# Example output:
# ErrorCode   : 0x80092013 (CRYPT_E_REVOCATION_OFFLINE)
# ErrorName   : CRYPT_E_REVOCATION_OFFLINE
# Severity    : Warning
# Certificate : CN=*.microsoft.com
# Thumbprint  : A1B2C3D4E5F6071829384756ABCDEF1234567890
# Description : Revocation server offline - cannot verify revocation status
# Resolution  : 1. Check network connectivity
#               2. Verify firewall allows access to CRL/OCSP URLs
#               3. Test CRL Distribution Points manually
```

#### **Expired Certificates**
```powershell
# Find certificate expiration issues
$ExpiredCerts = Find-CapiEventsByName -Name "*.contoso.com" -FilterType Expired
$Analysis = Get-CapiErrorAnalysis -Events $ExpiredCerts[0].Events

# Example output:
# ErrorCode   : 0x800B0101 (CERT_E_EXPIRED)
# ErrorName   : CERT_E_EXPIRED
# Severity    : Critical
# Certificate : CN=legacy.contoso.com
# Thumbprint  : 9876543210FEDCBA9876543210FEDCBA98765432
# Description : Certificate has expired and is not valid
# Resolution  : 1. Renew the certificate immediately
#               2. Verify system clock is correct
#               3. Check certificate NotAfter date
```

#### **Untrusted Certificates**
```powershell
# Find trust chain failures
$TrustIssues = Find-CapiEventsByName -Name "internal-site.com" -FilterType Untrusted
$Analysis = Get-CapiErrorAnalysis -Events $TrustIssues[0].Events

# Example output:
# ErrorCode   : 0x800B0109 (CERT_E_UNTRUSTEDROOT)
# ErrorName   : CERT_E_UNTRUSTEDROOT
# Severity    : Critical
# Certificate : CN=Internal Root CA
# Thumbprint  : FEDCBA0987654321FEDCBA0987654321FEDCBA09
# Description : Certificate chain terminates in untrusted root certificate
# Resolution  : 1. Install root CA certificate to Trusted Root store
#               2. Verify certificate chain is complete
#               3. Check Group Policy certificate deployment
```

#### **Chain Building Problems**
```powershell
# Find certificate chain construction failures
$ChainIssues = Find-CapiEventsByName -Name "api.example.com" -FilterType ChainBuilding
$Analysis = Get-CapiErrorAnalysis -Events $ChainIssues[0].Events

# Example output:
# ErrorCode   : 0x800B010A (CERT_E_CHAINING)
# ErrorName   : CERT_E_CHAINING
# Severity    : Critical
# Certificate : CN=api.example.com
# Thumbprint  : 1234567890ABCDEF1234567890ABCDEF12345678
# Function    : CertGetCertificateChain
# Description : Cannot build complete certificate chain to trusted root
# Resolution  : 1. Install missing intermediate certificates
#               2. Verify AIA (Authority Information Access) URLs are accessible
#               3. Check certificate store contains all chain members
```

#### **Policy Validation Failures**
```powershell
# Find certificate policy validation errors
$PolicyIssues = Find-CapiEventsByName -Name "secure.bank.com" -FilterType PolicyValidation
$Analysis = Get-CapiErrorAnalysis -Events $PolicyIssues[0].Events

# Example output:
# ErrorCode   : 0x800B0111 (CERT_E_WRONG_USAGE)
# ErrorName   : CERT_E_WRONG_USAGE
# Severity    : Critical
# Certificate : CN=secure.bank.com
# Thumbprint  : ABCDEF1234567890ABCDEF1234567890ABCDEF12
# Function    : CertVerifyCertificateChainPolicy
# Description : Certificate not valid for requested usage
# Resolution  : 1. Verify certificate has correct Enhanced Key Usage (EKU)
#               2. Request new certificate with Server Authentication (1.3.6.1.5.5.7.3.1)
#               3. Check application policy requirements
```

#### **Signature Validation**
```powershell
# Find digital signature verification failures
$SigIssues = Find-CapiEventsByName -Name "download.company.com" -FilterType SignatureValidation
$Analysis = Get-CapiErrorAnalysis -Events $SigIssues[0].Events

# Example output:
# ErrorCode   : 0x80096004 (TRUST_E_CERT_SIGNATURE)
# ErrorName   : TRUST_E_CERT_SIGNATURE
# Severity    : Critical
# Certificate : CN=Code Signing Certificate
# Thumbprint  : 567890ABCDEF1234567890ABCDEF1234567890AB
# Description : Certificate signature verification failed
# Resolution  : 1. Re-download certificate from trusted source
#               2. Verify certificate has not been tampered with
#               3. Check issuer certificate is valid and trusted
```

#### **All Errors Only**
```powershell
# Find all events with errors (Result value present)
$ErrorsOnly = Find-CapiEventsByName -Name "*.domain.com" -FilterType ErrorsOnly
$Analysis = Get-CapiErrorAnalysis -Events $ErrorsOnly[0].Events -IncludeSummary

# Example output summary:
# Total Errors    : 3
# Critical        : 2
# Warning         : 1
# Info            : 0
# Unique Errors   : 2 (CERT_E_EXPIRED, CRYPT_E_REVOCATION_OFFLINE)
# Certificates    : CN=app.domain.com, CN=api.domain.com
```

#### **Advanced: Custom Pattern Filtering**
```powershell
# For specific scenarios not covered by FilterType
$OCSPOnly = Find-CapiEventsByName -Name "site.com" -IncludePattern "OCSP"
$SpecificError = Find-CapiEventsByName -Name "site.com" -IncludePattern "*0x800B0101*"
$MultiPattern = Find-CapiEventsByName -Name "site.com" -IncludePattern "*CRL*|*AIA*"
```

### Example 6: Bulk Analysis and Reporting

```powershell
# ⭐ Simplified approach - exports each chain to separate file
$Sites = @("site1.com", "site2.com", "site3.com")
foreach ($Site in $Sites) {
    Get-CapiCertificateReport -Name $Site -ExportPath "C:\Reports" -Hours 168
}

# Advanced approach with more control - single file per site
$Sites = @("site1.com", "site2.com", "site3.com")
foreach ($Site in $Sites) {
    $Results = Find-CapiEventsByName -Name $Site -Hours 168
    
    if ($Results) {
        # Process each correlation chain for this site
        foreach ($Result in $Results) {
            $SafeSiteName = $Site -replace '[\\/:*?"<>|]', '_'
            $ShortTaskID = $Result.TaskID.Substring(0, 8)
            $OutputFile = "$SafeSiteName`_$ShortTaskID.html"
            
            Export-CapiEvents -Events $Result.Events -Path "C:\Reports\$OutputFile" -Format HTML -IncludeErrorAnalysis -TaskID $Result.TaskID
            Write-Host "✓ Exported $Site analysis to $OutputFile" -ForegroundColor Green
        }
    }
}
```

### Example 7: Comparative Error Analysis Across Environments

Compare certificate issues between production and staging environments:

```powershell
# Production environment analysis
Write-Host "`n=== Production Environment ===" -ForegroundColor Cyan
$ProdErrors = Find-CapiEventsByName -Name "*.prod.contoso.com" -FilterType ErrorsOnly -Hours 24
$ProdAnalysis = Get-CapiErrorAnalysis -Events $ProdErrors[0].Events

# Staging environment analysis
Write-Host "`n=== Staging Environment ===" -ForegroundColor Cyan
$StagingErrors = Find-CapiEventsByName -Name "*.staging.contoso.com" -FilterType ErrorsOnly -Hours 24
$StagingAnalysis = Get-CapiErrorAnalysis -Events $StagingErrors[0].Events

# Compare error types
Write-Host "`n=== Error Comparison ===" -ForegroundColor Yellow
$ProdErrorTypes = $ProdAnalysis | Group-Object ErrorName | Select-Object Name, Count
$StagingErrorTypes = $StagingAnalysis | Group-Object ErrorName | Select-Object Name, Count

# Create comparison table
$Comparison = @()
$AllErrorTypes = ($ProdErrorTypes.Name + $StagingErrorTypes.Name) | Select-Object -Unique

foreach ($ErrorType in $AllErrorTypes) {
    $ProdCount = ($ProdErrorTypes | Where-Object { $_.Name -eq $ErrorType }).Count
    $StageCount = ($StagingErrorTypes | Where-Object { $_.Name -eq $ErrorType }).Count
    
    $Comparison += [PSCustomObject]@{
        ErrorType = $ErrorType
        Production = if ($ProdCount) { $ProdCount } else { 0 }
        Staging = if ($StageCount) { $StageCount } else { 0 }
        Delta = ($ProdCount - $StageCount)
    }
}

$Comparison | Format-Table -AutoSize

# Example output:
# ErrorType                    Production Staging Delta
# ---------                    ---------- ------- -----
# CERT_E_EXPIRED                        3       0     3
# CRYPT_E_REVOCATION_OFFLINE            5       2     3
# CERT_E_UNTRUSTEDROOT                  0       4    -4
# CERT_E_CHAINING                       2       1     1

# Identify environment-specific issues
Write-Host "`n=== Production-Only Issues ===" -ForegroundColor Red
$Comparison | Where-Object { $_.Production -gt 0 -and $_.Staging -eq 0 } | Format-Table

Write-Host "`n=== Staging-Only Issues ===" -ForegroundColor Yellow
$Comparison | Where-Object { $_.Staging -gt 0 -and $_.Production -eq 0 } | Format-Table

# Deep dive into specific error type
Write-Host "`n=== Revocation Issues Detail ===" -ForegroundColor Yellow
$ProdRevocation = Find-CapiEventsByName -Name "*.prod.contoso.com" -FilterType Revocation
$StageRevocation = Find-CapiEventsByName -Name "*.staging.contoso.com" -FilterType Revocation

Write-Host "Production Revocation Failures:" -ForegroundColor White
Get-CapiErrorAnalysis -Events $ProdRevocation[0].Events | Select-Object Certificate, Thumbprint, ErrorName

# Output:
# Certificate              Thumbprint                               ErrorName
# -----------              ----------                               ---------
# CN=api.prod.contoso.com  A1B2C3D4E5F6071829384756ABCDEF1234567890 CRYPT_E_REVOCATION_OFFLINE
# CN=web.prod.contoso.com  1234567890ABCDEF1234567890ABCDEF12345678 CRYPT_E_REVOCATION_OFFLINE

Write-Host "`nStaging Revocation Failures:" -ForegroundColor White
Get-CapiErrorAnalysis -Events $StageRevocation[0].Events | Select-Object Certificate, Thumbprint, ErrorName

# Generate environment comparison report
Export-CapiEvents -Events $ProdErrors[0].Events `
                  -Path "C:\Reports\Prod_Analysis.html" `
                  -Format HTML `
                  -IncludeErrorAnalysis `
                  -TaskID $ProdErrors[0].TaskID

Export-CapiEvents -Events $StagingErrors[0].Events `
                  -Path "C:\Reports\Staging_Analysis.html" `
                  -Format HTML `
                  -IncludeErrorAnalysis `
                  -TaskID $StagingErrors[0].TaskID

Write-Host "`nReports generated for comparison" -ForegroundColor Green
```

### Example 8: Monitor Application Certificate Usage

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

### Example 8: Systematic Troubleshooting Workflow

This example demonstrates a complete troubleshooting workflow using different FilterTypes:

```powershell
# Step 1: Start with ErrorsOnly to get overview
Write-Host "`n=== Step 1: Finding All Errors ===" -ForegroundColor Cyan
$AllErrors = Find-CapiEventsByName -Name "*.contoso.com" -FilterType ErrorsOnly -Hours 24
$Summary = Get-CapiErrorAnalysis -Events $AllErrors[0].Events -IncludeSummary

# Output:
# Total Errors    : 8
# Critical        : 5
# Warning         : 3
# Info            : 0
# Unique Errors   : 4
# TaskID          : C4D5E6F7-8901-2345-6789-0ABCDEF12345

# Step 2: Check for expiration issues
Write-Host "`n=== Step 2: Checking Certificate Expiration ===" -ForegroundColor Yellow
$Expired = Find-CapiEventsByName -Name "*.contoso.com" -FilterType Expired -Hours 24
if ($Expired) {
    $ExpiredAnalysis = Get-CapiErrorAnalysis -Events $Expired[0].Events
    $ExpiredAnalysis | Format-Table ErrorName, Certificate, Thumbprint, Resolution -Wrap
    
    # Output:
    # ErrorName      Certificate              Thumbprint                               Resolution
    # ---------      -----------              ----------                               ----------
    # CERT_E_EXPIRED CN=old.contoso.com       DEAD1234BEEF5678DEAD1234BEEF5678DEAD1234 1. Renew certificate...
    # CERT_E_EXPIRED CN=Contoso Legacy CA     CAFE9876BABE5432CAFE9876BABE5432CAFE9876 1. Renew certificate...
    
    Write-Host "FOUND: $($ExpiredAnalysis.Count) expired certificate(s)" -ForegroundColor Red
} else {
    Write-Host "No expired certificates found" -ForegroundColor Green
}

# Step 3: Check for trust issues
Write-Host "`n=== Step 3: Checking Trust Chain ===" -ForegroundColor Yellow
$Untrusted = Find-CapiEventsByName -Name "*.contoso.com" -FilterType Untrusted -Hours 24
if ($Untrusted) {
    $TrustAnalysis = Get-CapiErrorAnalysis -Events $Untrusted[0].Events
    
    # Group by error type
    $TrustAnalysis | Group-Object ErrorName | Format-Table Count, Name -AutoSize
    
    # Output:
    # Count Name
    # ----- ----
    #     2 CERT_E_UNTRUSTEDROOT
    #     1 CERT_E_CHAINING
    
    Write-Host "FOUND: Trust chain issues detected" -ForegroundColor Red
} else {
    Write-Host "Trust chain is valid" -ForegroundColor Green
}

# Step 4: Check revocation status
Write-Host "`n=== Step 4: Checking Revocation Status ===" -ForegroundColor Yellow
$Revocation = Find-CapiEventsByName -Name "*.contoso.com" -FilterType Revocation -Hours 24
if ($Revocation) {
    $RevAnalysis = Get-CapiErrorAnalysis -Events $Revocation[0].Events
    
    # Extract CRL/OCSP URLs from events
    $RevAnalysis | ForEach-Object {
        Write-Host "Certificate: $($_.Certificate)" -ForegroundColor White
        Write-Host "Error: $($_.ErrorName)" -ForegroundColor Red
        Write-Host "Thumbprint: $($_.Thumbprint)" -ForegroundColor Gray
        Write-Host ""
    }
    
    # Output:
    # Certificate: CN=app.contoso.com
    # Error: CRYPT_E_REVOCATION_OFFLINE
    # Thumbprint: ABC123DEF456ABC123DEF456ABC123DEF456ABC1
    
    Write-Host "FOUND: $($RevAnalysis.Count) revocation check failure(s)" -ForegroundColor Red
} else {
    Write-Host "Revocation checks successful" -ForegroundColor Green
}

# Step 5: Detailed chain analysis
Write-Host "`n=== Step 5: Detailed Chain Analysis ===" -ForegroundColor Yellow
$ChainIssues = Find-CapiEventsByName -Name "*.contoso.com" -FilterType ChainBuilding -Hours 24
if ($ChainIssues) {
    $ChainAnalysis = Get-CapiErrorAnalysis -Events $ChainIssues[0].Events
    
    # Show which certificates are missing
    $ChainAnalysis | Where-Object { $_.ErrorName -eq 'CERT_E_CHAINING' } | ForEach-Object {
        Write-Host "Missing intermediate for: $($_.Certificate)" -ForegroundColor Red
        Write-Host "Thumbprint: $($_.Thumbprint)" -ForegroundColor Gray
        Write-Host "Resolution: $($_.Resolution[0])" -ForegroundColor Yellow
        Write-Host ""
    }
}

# Step 6: Generate comprehensive report
Write-Host "`n=== Step 6: Generating Report ===" -ForegroundColor Cyan
Export-CapiEvents -Events $AllErrors[0].Events `
                  -Path "C:\Reports" `
                  -Format HTML `
                  -IncludeErrorAnalysis `
                  -TaskID $AllErrors[0].TaskID

Write-Host "Report saved to: C:\Reports\CapiEvents_$($AllErrors[0].TaskID.Substring(0,8)).html" -ForegroundColor Green

# Step 7: Summary and recommendations
Write-Host "`n=== Troubleshooting Summary ===" -ForegroundColor Cyan
Write-Host "Total Issues Found: $($Summary.TotalErrors)" -ForegroundColor White
Write-Host "Critical: $($Summary.Critical) | Warning: $($Summary.Warning)" -ForegroundColor White
Write-Host "`nRecommended Actions:" -ForegroundColor Yellow
Write-Host "1. Renew expired certificates immediately" -ForegroundColor White
Write-Host "2. Install missing intermediate certificates" -ForegroundColor White
Write-Host "3. Deploy root CA certificates via Group Policy" -ForegroundColor White
Write-Host "4. Verify network access to CRL/OCSP endpoints" -ForegroundColor White
```

### Example 10: Automated Certificate Monitoring with Alerts

Scheduled task for proactive certificate monitoring using FilterType:

```powershell
# Certificate Health Monitoring Script
# Schedule this to run hourly via Task Scheduler

$MonitoringConfig = @{
    Domains = @("*.contoso.com", "*.api.contoso.com", "*.internal.local")
    Hours = 2
    AlertEmail = "it-security@contoso.com"
    ReportPath = "C:\CertMonitoring\Reports"
}

# Initialize alert tracking
$Alerts = @()

# Check 1: Expired certificates (CRITICAL)
Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Checking for expired certificates..." -ForegroundColor Cyan
foreach ($Domain in $MonitoringConfig.Domains) {
    $Expired = Find-CapiEventsByName -Name $Domain -FilterType Expired -Hours $MonitoringConfig.Hours
    
    if ($Expired) {
        $Analysis = Get-CapiErrorAnalysis -Events $Expired[0].Events
        foreach ($Error in $Analysis) {
            $Alerts += [PSCustomObject]@{
                Timestamp = Get-Date
                Severity = "CRITICAL"
                Type = "Expired Certificate"
                Domain = $Domain
                Certificate = $Error.Certificate
                Thumbprint = $Error.Thumbprint
                ErrorCode = $Error.ErrorCode
                Message = "Certificate has expired"
            }
            Write-Host "  [CRITICAL] Expired: $($Error.Certificate)" -ForegroundColor Red
        }
    }
}

# Check 2: Untrusted certificates (CRITICAL)
Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Checking for trust chain issues..." -ForegroundColor Cyan
foreach ($Domain in $MonitoringConfig.Domains) {
    $Untrusted = Find-CapiEventsByName -Name $Domain -FilterType Untrusted -Hours $MonitoringConfig.Hours
    
    if ($Untrusted) {
        $Analysis = Get-CapiErrorAnalysis -Events $Untrusted[0].Events
        foreach ($Error in $Analysis) {
            $Alerts += [PSCustomObject]@{
                Timestamp = Get-Date
                Severity = "CRITICAL"
                Type = "Untrusted Certificate"
                Domain = $Domain
                Certificate = $Error.Certificate
                Thumbprint = $Error.Thumbprint
                ErrorCode = $Error.ErrorCode
                Message = $Error.Description
            }
            Write-Host "  [CRITICAL] Untrusted: $($Error.Certificate)" -ForegroundColor Red
        }
    }
}

# Check 3: Revocation check failures (WARNING)
Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Checking revocation status..." -ForegroundColor Cyan
foreach ($Domain in $MonitoringConfig.Domains) {
    $Revocation = Find-CapiEventsByName -Name $Domain -FilterType Revocation -Hours $MonitoringConfig.Hours
    
    if ($Revocation) {
        $Analysis = Get-CapiErrorAnalysis -Events $Revocation[0].Events
        foreach ($Error in $Analysis) {
            $Alerts += [PSCustomObject]@{
                Timestamp = Get-Date
                Severity = "WARNING"
                Type = "Revocation Check Failed"
                Domain = $Domain
                Certificate = $Error.Certificate
                Thumbprint = $Error.Thumbprint
                ErrorCode = $Error.ErrorCode
                Message = "CRL/OCSP server unreachable"
            }
            Write-Host "  [WARNING] Revocation failed: $($Error.Certificate)" -ForegroundColor Yellow
        }
    }
}

# Check 4: Chain building issues (CRITICAL)
Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Checking certificate chains..." -ForegroundColor Cyan
foreach ($Domain in $MonitoringConfig.Domains) {
    $ChainIssues = Find-CapiEventsByName -Name $Domain -FilterType ChainBuilding -Hours $MonitoringConfig.Hours
    
    if ($ChainIssues) {
        $Analysis = Get-CapiErrorAnalysis -Events $ChainIssues[0].Events
        foreach ($Error in $Analysis) {
            $Alerts += [PSCustomObject]@{
                Timestamp = Get-Date
                Severity = "CRITICAL"
                Type = "Chain Building Failed"
                Domain = $Domain
                Certificate = $Error.Certificate
                Thumbprint = $Error.Thumbprint
                ErrorCode = $Error.ErrorCode
                Message = "Missing intermediate certificates"
            }
            Write-Host "  [CRITICAL] Chain failure: $($Error.Certificate)" -ForegroundColor Red
        }
    }
}

# Generate summary report
Write-Host "`n=== Monitoring Summary ===" -ForegroundColor Cyan
$CriticalCount = ($Alerts | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$WarningCount = ($Alerts | Where-Object { $_.Severity -eq "WARNING" }).Count

Write-Host "Total Alerts: $($Alerts.Count)" -ForegroundColor White
Write-Host "Critical: $CriticalCount | Warnings: $WarningCount" -ForegroundColor White

if ($Alerts.Count -gt 0) {
    # Display alerts
    $Alerts | Format-Table Timestamp, Severity, Type, Certificate, Thumbprint -AutoSize
    
    # Example output:
    # Timestamp           Severity Type                    Certificate              Thumbprint
    # ---------           -------- ----                    -----------              ----------
    # 12/10/2025 14:30:15 CRITICAL Expired Certificate     CN=old.contoso.com       DEAD1234BEEF5678...
    # 12/10/2025 14:30:16 CRITICAL Untrusted Certificate   CN=Internal Root CA      FEDCBA0987654321...
    # 12/10/2025 14:30:18 WARNING  Revocation Check Failed CN=api.contoso.com       A1B2C3D4E5F6071829...
    # 12/10/2025 14:30:20 CRITICAL Chain Building Failed   CN=secure.contoso.com    1234567890ABCDEF...
    
    # Export detailed report
    $ReportFile = Join-Path $MonitoringConfig.ReportPath "CertAlert_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $Alerts | ConvertTo-Html -Title "Certificate Alert Report" | Out-File $ReportFile
    
    # Send email alert (if critical issues found)
    if ($CriticalCount -gt 0) {
        $EmailBody = @"
Certificate Monitoring Alert - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

CRITICAL ISSUES DETECTED: $CriticalCount
Warnings: $WarningCount

Summary:
$($Alerts | Where-Object { $_.Severity -eq "CRITICAL" } | Format-Table Type, Certificate, Message | Out-String)

Full report: $ReportFile

Action Required:
1. Review expired certificates and renew immediately
2. Verify certificate trust chains
3. Install missing intermediate certificates
4. Check CRL/OCSP endpoint accessibility

This is an automated alert from CAPI2Tools Certificate Monitoring.
"@
        
        # Uncomment to send email:
        # Send-MailMessage -To $MonitoringConfig.AlertEmail `
        #                  -From "certmonitor@contoso.com" `
        #                  -Subject "[CRITICAL] Certificate Issues Detected - $CriticalCount Critical" `
        #                  -Body $EmailBody `
        #                  -SmtpServer "smtp.contoso.com"
        
        Write-Host "`n[ALERT] Email notification would be sent to $($MonitoringConfig.AlertEmail)" -ForegroundColor Red
    }
    
    Write-Host "`nReport saved: $ReportFile" -ForegroundColor Green
} else {
    Write-Host "`n[OK] No certificate issues detected" -ForegroundColor Green
}

# Log to Windows Event Log
$EventSource = "CAPI2Tools-Monitor"
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    New-EventLog -LogName Application -Source $EventSource
}

$EventType = if ($CriticalCount -gt 0) { "Error" } elseif ($WarningCount -gt 0) { "Warning" } else { "Information" }
$EventMessage = "Certificate monitoring complete. Critical: $CriticalCount, Warnings: $WarningCount"
Write-EventLog -LogName Application -Source $EventSource -EntryType $EventType -EventId 1001 -Message $EventMessage

Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Monitoring cycle complete" -ForegroundColor Cyan
```

### Example 11: Process Multiple Certificate Chains

```powershell
# Find all microsoft.com certificate validations in last 5 hours
$Results = Find-CapiEventsByName -Name "microsoft.com" -Hours 5

# Display all TaskIDs found
$Results | Select-Object -Property TaskID

# Process each chain individually
foreach ($Result in $Results) {
    Write-Host "`n=== Processing TaskID: $($Result.TaskID) ===" -ForegroundColor Cyan
    
    # Get full event chain
    $Events = Get-CapiTaskIDEvents -TaskID $Result.TaskID
    
    # Analyze for errors
    $ErrorAnalysis = Get-CapiErrorAnalysis -Events $Events
    
    # Export to separate file
    if ($ErrorAnalysis) {
        $FileName = "microsoft_$($Result.TaskID.Substring(0,8)).html"
        Export-CapiEvents -Events $Events -Path "C:\Reports" -Format HTML -IncludeErrorAnalysis -TaskID $Result.TaskID
        Write-Host "Exported: $FileName" -ForegroundColor Green
    }
}

# Or use the simplified approach for single chain
$TaskID = ($Results | Select-Object -First 1).TaskID
Get-CapiTaskIDEvents -TaskID $TaskID | Get-CapiErrorAnalysis -IncludeSummary
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
|---------|------|---------||
| 2.10.1 | December 2025 | Event ID 82 support (catalog lookup failures), 13 new error codes (ERROR_NOT_FOUND, CERT_E_PURPOSE, SEC_E_WRONG_PRINCIPAL, TRUST_E_BAD_DIGEST, etc.), certificate thumbprint extraction and display, enhanced enterprise diagnostics |
| 2.10 | December 2025 | TrustStatus parsing with 23 ErrorStatus and 13 InfoStatus flags, enhanced error analysis with detailed trust chain validation, improved HTML reports with trust details column, automatic severity tracking (Critical/Error/Warning), comprehensive certificate chain diagnostics |
| 2.9 | December 2025 | Multi-file export (each chain to separate file), smart auto-generated filenames, directory-based ExportPath, Format parameter with ValidateSet, eliminated file overwrite issues |
| 2.8 | December 2025 | Enhanced multi-field search (SubjectAltName, CN, ProcessName), process-based correlation, simplified usage with automatic field searching, priority-based matching |
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
     
