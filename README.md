# CAPI2 Event Log Correlation Toolkit

[![Version](https://img.shields.io/badge/version-2.5-blue.svg)](https://github.com/BetaHydri/GetCapiCorrelationTask)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)
[![Author](https://img.shields.io/badge/author-Jan%20Tiedemann-orange.svg)](https://github.com/BetaHydri)

A powerful PowerShell toolkit for analyzing Windows CAPI2 (Cryptographic API) event logs, enabling administrators to troubleshoot certificate validation, TLS/SSL connection issues, and certificate chain building problems.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Event Log Management](#event-log-management)
  - [Search by DNS/Certificate Name](#search-by-dnscertificate-name)
  - [Error Analysis](#error-analysis)
  - [Export Functionality](#export-functionality)
  - [Comparison Features](#comparison-features)
- [Functions](#functions)
- [Examples](#examples)
- [Error Codes Reference](#error-codes-reference)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## 🔍 Overview

The CAPI2 Event Log Correlation Toolkit simplifies the complex task of analyzing certificate validation chains in Windows. When applications establish secure connections (TLS/SSL), Windows logs detailed cryptographic operations to the CAPI2 event log. These events are correlated using a TaskID (GUID), but finding the right correlation chain traditionally required manual searching.

**Version 2.5** introduces comprehensive error analysis, event log management, export capabilities, and comparison features.

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

### Complete Troubleshooting Workflow

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

### Example 1: Complete Troubleshooting Session

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

### Example 2: Track Fix Progress

```powershell
# Capture baseline
$Before = Find-CapiEventsByName -Name "myapp.company.com"

# Apply certificate fix

# Test again
$After = Find-CapiEventsByName -Name "myapp.company.com"

# Compare results
Compare-CapiEvents -ReferenceEvents $Before[0].Events -DifferenceEvents $After[0].Events
```

### Example 3: Investigate Specific Error

```powershell
# Find events with revocation errors
$Results = Find-CapiEventsByName -Name "*.microsoft.com" -IncludePattern "revocation"

# Analyze first chain
$Analysis = Get-CapiErrorAnalysis -Events $Results[0].Events

# Filter for critical errors only
$CriticalErrors = $Analysis | Where-Object { $_.Severity -eq "Critical" }
$CriticalErrors | Format-Table ErrorName, Certificate, Resolution -Wrap
```

### Example 4: Bulk Analysis and Reporting

```powershell
# Search for multiple sites
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

### Example 5: Monitor Application Certificate Usage

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
     
                          RSA TLS CA 01</CN><O>Microsoft Corporation</O><C>US</C></Subject><SubjectKeyID computed="false"
                          hash="B5760C3011CEC792424D4CC75C2CC8A90CE80B64" /><SignatureAlgorithm oid="1.2.840.113549.1.1.11" hashName="SHA256"     
                          publicKeyName="RSA" /><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1" publicKeyName="RSA" publicKeyLength="4096"
                          /><Issuer><CN>Baltimore CyberTrust Root</CN><OU>CyberTrust</OU><O>Baltimore</O><C>IE</C></Issuer><SerialNumber>0F14965F 
                          202069994FD5C7AC788941E2</SerialNumber><NotBefore>2020-07-21T23:00:00Z</NotBefore><NotAfter>2024-10-08T07:00:00Z</NotAf 
                          ter><Extensions><AuthorityKeyIdentifier><KeyID hash="E59D5930824758CCACFA085436867B3AB5044DF0"
                          /></AuthorityKeyIdentifier><KeyUsage critical="true" value="86" CERT_DIGITAL_SIGNATURE_KEY_USAGE="true"
                          CERT_KEY_CERT_SIGN_KEY_USAGE="true" CERT_CRL_SIGN_KEY_USAGE="true" /><ExtendedKeyUsage><Usage oid="1.3.6.1.5.5.7.3.1"   
                          name="Serverauthentifizierung" /><Usage oid="1.3.6.1.5.5.7.3.2" name="Clientauthentifizierung" 
                          /></ExtendedKeyUsage><BasicConstraints critical="true" cA="true" pathLenConstraint="0" /><CertificatePolicies><Policy   
                          oid="2.23.140.1.2.1" /><Policy oid="2.23.140.1.2.2" /><Policy oid="1.3.6.1.4.1.311.42.1"
                          /></CertificatePolicies></Extensions></Certificate><Certificate fileRef="930F5167FA5112F077FC65AB3DFFE8A347F5BD9B.cer"  
                          subjectName="r.bing.com"><Subject><CN>r.bing.com</CN><O>Microsoft
                          Corporation</O><L>Redmond</L><S>WA</S><C>US</C></Subject><SubjectKeyID computed="false"
                          hash="F6CB10F1E887FD3C75E0CCB02C76B7DBA56A0517" /><SignatureAlgorithm oid="1.2.840.113549.1.1.11" hashName="SHA256"     
                          publicKeyName="RSA" /><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1" publicKeyName="RSA" publicKeyLength="2048"
                          /><Issuer><CN>Microsoft RSA TLS CA 01</CN><O>Microsoft Corporation</O><C>US</C></Issuer><SerialNumber>12001EA96F3C9E29F 
                          709C4E56D0000001EA96F</SerialNumber><NotBefore>2021-12-07T20:58:22Z</NotBefore><NotAfter>2022-12-07T20:58:22Z</NotAfter 
                          ><Extensions><KeyUsage critical="true" value="B0" CERT_DIGITAL_SIGNATURE_KEY_USAGE="true"
                          CERT_KEY_ENCIPHERMENT_KEY_USAGE="true" CERT_DATA_ENCIPHERMENT_KEY_USAGE="true" /><SubjectAltName><DNSName>r.bing.com</D 
                          NSName><DNSName>thaka.msftstatic.com</DNSName><DNSName>thaka.bing.com</DNSName><DNSName>th.msftstatic.com</DNSName><DNS 
                          Name>th.bing.com</DNSName><DNSName>raka.msftstatic.com</DNSName><DNSName>raka.bing.com</DNSName><DNSName>r.msftstatic.c 
                          om</DNSName><DNSName>akam.bing.com</DNSName><DNSName>*.mm.bing.net</DNSName><DNSName>*.explicit.bing.net</DNSName><DNSN 
                          ame>*.bingstatic.com</DNSName><DNSName>*.bing.com</DNSName></SubjectAltName><CertificatePolicies><Policy
                          oid="1.3.6.1.4.1.311.42.1" /><Policy oid="2.23.140.1.2.2" /></CertificatePolicies><AuthorityKeyIdentifier><KeyID        
                          hash="B5760C3011CEC792424D4CC75C2CC8A90CE80B64" /></AuthorityKeyIdentifier><ExtendedKeyUsage><Usage
                          oid="1.3.6.1.5.5.7.3.2" name="Clientauthentifizierung" /><Usage oid="1.3.6.1.5.5.7.3.1" name="Serverauthentifizierung"  
                          /></ExtendedKeyUsage></Extensions></Certificate><OCSPResponse fileRef="D3B95EBB9474B2AC60FEE68BF670ACCF0168CEDE.bin"    
                          issuerName="Baltimore CyberTrust Root"><Status
                          value="0">OCSP_SUCCESSFUL_RESPONSE</Status><ProducedAt>2022-10-25T04:31:18Z</ProducedAt><Issuer><CN>Baltimore
                          CyberTrust Root</CN><OU>CyberTrust</OU><O>Baltimore</O><C>IE</C></Issuer><DelegatedSigner><CN>Baltimore Cybertrust      
                          Validation 2025</CN><O>DigiCert,
                          Inc.</O><C>US</C></DelegatedSigner><Response><SerialNumber>0F14965F202069994FD5C7AC788941E2</SerialNumber><CertStatus v 
                          alue="0">OCSP_BASIC_GOOD_CERT_STATUS</CertStatus><ThisUpdate>2022-10-25T04:15:02Z</ThisUpdate><NextUpdate>2022-11-01T03 
                          :30:02Z</NextUpdate></Response></OCSPResponse><Certificate fileRef="D4DE20D05E66FC53FE1A50882C78DB2852CAE474.cer"       
                          subjectName="Baltimore CyberTrust Root"><Subject><CN>Baltimore CyberTrust
                          Root</CN><OU>CyberTrust</OU><O>Baltimore</O><C>IE</C></Subject><SubjectKeyID computed="false"
                          hash="E59D5930824758CCACFA085436867B3AB5044DF0" /><SignatureAlgorithm oid="1.2.840.113549.1.1.5" hashName="SHA1"        
                          publicKeyName="RSA" /><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1" publicKeyName="RSA" publicKeyLength="2048"
                          /><Issuer><CN>Baltimore CyberTrust Root</CN><OU>CyberTrust</OU><O>Baltimore</O><C>IE</C></Issuer><SerialNumber>020000B9 
                          </SerialNumber><NotBefore>2000-05-12T18:46:00Z</NotBefore><NotAfter>2025-05-12T23:59:00Z</NotAfter><Extensions><BasicCo 
                          nstraints critical="true" cA="true" pathLenConstraint="3" /><KeyUsage critical="true" value="06"
                          CERT_KEY_CERT_SIGN_KEY_USAGE="true" CERT_CRL_SIGN_KEY_USAGE="true" /></Extensions><Properties><ExtendedKeyUsage><Usage  
                          oid="1.3.6.1.5.5.7.3.2" name="Clientauthentifizierung" /><Usage oid="1.3.6.1.5.5.7.3.3" name="Codesignatur" /><Usage    
                          oid="1.3.6.1.5.5.7.3.4" name="Sichere E-Mail" /><Usage oid="1.3.6.1.5.5.7.3.9" name="OCSP-Signatur" /><Usage
                          oid="1.3.6.1.5.5.7.3.1" name="Serverauthentifizierung" /><Usage oid="1.3.6.1.5.5.7.3.8" name="Zeitstempel"
                          /></ExtendedKeyUsage><FriendlyName>DigiCert Baltimore Root</FriendlyName><PoliciesInfo><PolicyInfo
                          certPolicyId="1.3.6.1.4.1.6334.1.100.1"><RootProgramPolicyQualifierInfo
                          policyQualifierId="1.3.6.1.4.1.311.60.1.1"><Qualifiers value="C0" CERT_ROOT_PROGRAM_FLAG_ORG="true"
                          CERT_ROOT_PROGRAM_FLAG_LSC="true" /></RootProgramPolicyQualifierInfo></PolicyInfo><PolicyInfo
                          certPolicyId="2.16.840.1.114412.2.1"><RootProgramPolicyQualifierInfo
                          policyQualifierId="1.3.6.1.4.1.311.60.1.1"><Qualifiers value="C0" CERT_ROOT_PROGRAM_FLAG_ORG="true"
                          CERT_ROOT_PROGRAM_FLAG_LSC="true" /></RootProgramPolicyQualifierInfo></PolicyInfo><PolicyInfo
                          certPolicyId="2.23.140.1.1"><RootProgramPolicyQualifierInfo policyQualifierId="1.3.6.1.4.1.311.60.1.1"><Qualifiers      
                          value="C0" CERT_ROOT_PROGRAM_FLAG_ORG="true" CERT_ROOT_PROGRAM_FLAG_LSC="true"
                          /></RootProgramPolicyQualifierInfo></PolicyInfo><PolicyInfo
                          certPolicyId="2.23.140.1.3"><RootProgramPolicyQualifierInfo policyQualifierId="1.3.6.1.4.1.311.60.1.1"><Qualifiers      
                          value="C0" CERT_ROOT_PROGRAM_FLAG_ORG="true" CERT_ROOT_PROGRAM_FLAG_LSC="true"
                          /></RootProgramPolicyQualifierInfo></PolicyInfo></PoliciesInfo></Properties></Certificate><CertificateRevocationList    
                          fileRef="44649D4C2634C2B5BD91AB9E0A70C5EAFC8B864A.crl" issuerName="Microsoft RSA TLS CA 01"><Issuer><CN>Microsoft RSA   
                          TLS CA 01</CN><O>Microsoft Corporation</O><C>US</C></Issuer><ThisUpdate>2022-10-10T21:49:58Z</ThisUpdate><NextUpdate>20 
                          22-10-18T22:09:58Z</NextUpdate><Extensions><AuthorityKeyIdentifier><KeyID
                          hash="B5760C3011CEC792424D4CC75C2CC8A90CE80B64" /></AuthorityKeyIdentifier><CRLNumber>010D</CRLNumber><NextPublishTime> 
                          2022-10-14T21:59:58Z</NextPublishTime></Extensions></CertificateRevocationList><EventAuxInfo ProcessName="msedge.exe"   
                          /><CorrelationAuxInfo TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="9" /></X509Objects>

        TimeCreated     : 10/25/2022 3:48:50 PM
        ID              : 11
        RecordType      : Fehler
        DetailedMessage : <CertGetCertificateChain xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Certificate
                          fileRef="930F5167FA5112F077FC65AB3DFFE8A347F5BD9B.cer" subjectName="r.bing.com" /><AdditionalStore><Certificate
                          fileRef="703D7A8F0EBF55AAA59F98EAF4A206004EB2516A.cer" subjectName="Microsoft RSA TLS CA 01" /><Certificate
                          fileRef="930F5167FA5112F077FC65AB3DFFE8A347F5BD9B.cer" subjectName="r.bing.com" /></AdditionalStore><ExtendedKeyUsage   
                          orMatch="true"><Usage oid="1.3.6.1.5.5.7.3.1" name="Serverauthentifizierung" /><Usage oid="1.3.6.1.4.1.311.10.3.3"      
                          /><Usage oid="2.16.840.1.113730.4.1" /></ExtendedKeyUsage><StrongSignPara
                          signHashList="RSA/SHA256;RSA/SHA384;RSA/SHA512;ECDSA/SHA256;ECDSA/SHA384;ECDSA/SHA512"
                          publicKeyList="RSA/1024;ECDSA/256" /><Flags value="A0000000" CERT_CHAIN_REVOCATION_CHECK_CHAIN="true"
                          CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY="true" /><ChainEngineInfo context="user" /><CertificateChain
                          chainRef="{0329F7C5-3224-41B2-ACF9-A79196D86FF8}"><TrustStatus><ErrorStatus value="1000040"
                          CERT_TRUST_REVOCATION_STATUS_UNKNOWN="true" CERT_TRUST_IS_OFFLINE_REVOCATION="true" /><InfoStatus value="100"
                          CERT_TRUST_HAS_PREFERRED_ISSUER="true" /></TrustStatus><ChainElement><Certificate
                          fileRef="930F5167FA5112F077FC65AB3DFFE8A347F5BD9B.cer" subjectName="r.bing.com" /><SignatureAlgorithm
                          oid="1.2.840.113549.1.1.11" hashName="SHA256" publicKeyName="RSA" /><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1"      
                          publicKeyName="RSA" publicKeyLength="2048" /><TrustStatus><ErrorStatus value="1000040"
                          CERT_TRUST_REVOCATION_STATUS_UNKNOWN="true" CERT_TRUST_IS_OFFLINE_REVOCATION="true" /><InfoStatus value="102"
                          CERT_TRUST_HAS_KEY_MATCH_ISSUER="true" CERT_TRUST_HAS_PREFERRED_ISSUER="true" /></TrustStatus><ApplicationUsage><Usage  
                          oid="1.3.6.1.5.5.7.3.2" name="Clientauthentifizierung" /><Usage oid="1.3.6.1.5.5.7.3.1" name="Serverauthentifizierung"  
                          /></ApplicationUsage><IssuanceUsage><Usage oid="2.23.140.1.2.2" /><Usage oid="1.3.6.1.4.1.311.42.1"
                          /></IssuanceUsage><RevocationInfo freshnessTime="P14DT15H58M52S"><RevocationResult value="80092013">Die Sperrfunktion   
                          konnte die Sperrung nicht überprüfen, da der Sperrserver offline war.</RevocationResult><StrongSignProperties
                          signHash="RSA/SHA256" issuerPublicKeyLength="4096" /><CertificateRevocationList location="TvoCache"
                          fileRef="44649D4C2634C2B5BD91AB9E0A70C5EAFC8B864A.crl" issuerName="Microsoft RSA TLS CA 01"
                          /></RevocationInfo></ChainElement><ChainElement><Certificate fileRef="703D7A8F0EBF55AAA59F98EAF4A206004EB2516A.cer"     
                          subjectName="Microsoft RSA TLS CA 01" /><SignatureAlgorithm oid="1.2.840.113549.1.1.11" hashName="SHA256"
                          publicKeyName="RSA" /><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1" publicKeyName="RSA" publicKeyLength="4096"
                          /><TrustStatus><ErrorStatus value="0" /><InfoStatus value="102" CERT_TRUST_HAS_KEY_MATCH_ISSUER="true"
                          CERT_TRUST_HAS_PREFERRED_ISSUER="true" /></TrustStatus><ApplicationUsage><Usage oid="1.3.6.1.5.5.7.3.1"
                          name="Serverauthentifizierung" /><Usage oid="1.3.6.1.5.5.7.3.2" name="Clientauthentifizierung"
                          /></ApplicationUsage><IssuanceUsage><Usage oid="2.23.140.1.2.1" /><Usage oid="2.23.140.1.2.2" /><Usage
                          oid="1.3.6.1.4.1.311.42.1" /></IssuanceUsage><RevocationInfo freshnessTime="PT9H33M48S"><RevocationResult value="0"     
                          /><StrongSignProperties signHash="RSA/SHA256" issuerPublicKeyLength="2048" issuerSignHashList="RSA/SHA256"
                          /><OCSPResponse location="TvoCache" fileRef="D3B95EBB9474B2AC60FEE68BF670ACCF0168CEDE.bin" issuerName="Baltimore        
                          CyberTrust Root" /></RevocationInfo></ChainElement><ChainElement><Certificate
                          fileRef="D4DE20D05E66FC53FE1A50882C78DB2852CAE474.cer" subjectName="Baltimore CyberTrust Root" /><SignatureAlgorithm    
                          oid="1.2.840.113549.1.1.5" hashName="SHA1" publicKeyName="RSA" /><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1"
                          publicKeyName="RSA" publicKeyLength="2048" /><TrustStatus><ErrorStatus value="0" /><InfoStatus value="10C"
                          CERT_TRUST_HAS_NAME_MATCH_ISSUER="true" CERT_TRUST_IS_SELF_SIGNED="true" CERT_TRUST_HAS_PREFERRED_ISSUER="true"
                          /></TrustStatus><ApplicationUsage><Usage oid="1.3.6.1.5.5.7.3.2" name="Clientauthentifizierung" /><Usage
                          oid="1.3.6.1.5.5.7.3.3" name="Codesignatur" /><Usage oid="1.3.6.1.5.5.7.3.4" name="Sichere E-Mail" /><Usage
                          oid="1.3.6.1.5.5.7.3.9" name="OCSP-Signatur" /><Usage oid="1.3.6.1.5.5.7.3.1" name="Serverauthentifizierung" /><Usage   
                          oid="1.3.6.1.5.5.7.3.8" name="Zeitstempel" /></ApplicationUsage><IssuanceUsage any="true"
                          /><RevocationInfo><RevocationResult value="0" /></RevocationInfo></ChainElement></CertificateChain><EventAuxInfo        
                          ProcessName="msedge.exe" /><CorrelationAuxInfo TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="10"
                          /><Result value="80092013">Die Sperrfunktion konnte die Sperrung nicht überprüfen, da der Sperrserver offline
                          war.</Result></CertGetCertificateChain>

</details>
