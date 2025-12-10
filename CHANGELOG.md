# Changelog

All notable changes to the CAPI2 Event Log Correlation Toolkit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.8.0] - 2025-12-10

### Added
- **Enhanced Multi-Field Search**: `Find-CapiEventsByName` now searches across multiple certificate and process fields:
  - `subjectName` attribute (most common in Event ID 30)
  - `CN` (Common Name) elements in certificate subjects
  - `SubjectAltName/DNSName` elements (SAN fields in Event ID 90)
  - `ProcessName` attribute (via EventAuxInfo in Event ID 30)
  - Full XML string search as fallback
- **Process-Based Correlation**: Can now search for certificate validations by process name (e.g., "chrome.exe", "outlook.exe", "GlobalSecureAccessClient.exe")
- **Priority-Based Search**: Implements intelligent search order for faster, more accurate results

### Changed
- **Get-CapiCertificateReport**: Now automatically benefits from enhanced multi-field search - simply use `-Name` parameter with any certificate field or process name
- **Search Documentation**: Updated help documentation with new examples showing process-based searches
- **Parameter Description**: Enhanced `-Name` parameter documentation to clearly indicate all searchable fields

### Improved
- **User Experience**: Simplified usage - no need to specify which field to search, the toolkit automatically searches all relevant fields
- **Search Accuracy**: Priority-based matching ensures most relevant results are found first
- **Performance**: Efficient XML parsing with early termination when match is found

---

## [2.7.0] - 2025-12-10

### Fixed
- **Critical Bug**: Fixed correlation chain retrieval - now properly uses BOTH chainRef and CorrelationAuxInfo TaskId for complete event chains
- **Error Detection**: Corrected XML namespace handling in `Get-CapiErrorAnalysis` - removed incorrect `<root>` wrapper that broke XPath queries
- **Error Code Normalization**: Enhanced `Get-CAPI2ErrorDetails` to handle hex codes without "0x" prefix (e.g., "800B0101" → "0x800B0101")
- **XPath Queries**: Updated to use `local-name()` function for namespace-agnostic XML element selection

### Changed
- **Correlation Mechanism**: `Get-CapiTaskIDEvents` now implements dual correlation strategy:
  1. First searches by chainRef (for certificate chain events: IDs 11, 30, 81)
  2. Then extracts CorrelationAuxInfo TaskId to retrieve full workflow (IDs 10, 11, 30, 40, 41, 50, 51, 80, 81, 90)
  3. Falls back to direct TaskId search for legacy events
- **Event Retrieval**: Modern Windows CAPI2 logging behavior now properly supported (typically 3-4 events for simple validations, 8+ for complex workflows)
- **XPath Expressions**: Updated correlation queries to support both modern chainRef attributes and legacy CorrelationAuxInfo structure

### Added
- **Better Error Reporting**: Error analysis now correctly identifies certificate expiration (CERT_E_EXPIRED), untrusted roots (CERT_E_UNTRUSTEDROOT), and name mismatches (CERT_E_CN_NO_MATCH)
- **Validation**: Comprehensive testing with badssl.com scenarios (expired, self-signed, wrong-host certificates)

---

## [2.5.0] - 2025-12-10

### Added
- **Module Conversion**: Converted from standalone script to proper PowerShell module with manifest (.psd1) and module file (.psm1)
- **New Function**: `Get-CapiErrorAnalysis` - Intelligent error analysis with human-readable descriptions, severity levels, common causes, and resolution steps
- **New Function**: `Export-CapiEvents` - Export events to multiple formats (CSV, JSON, HTML, XML) with optional error analysis integration
- **New Function**: `Compare-CapiEvents` - Compare before/after correlation chains to identify resolved, new, or persistent errors
- **New Function**: `Enable-CAPI2EventLog` - Enable CAPI2 Operational event log with administrator privilege check
- **New Function**: `Disable-CAPI2EventLog` - Disable CAPI2 logging to conserve system resources
- **New Function**: `Clear-CAPI2EventLog` - Clear event log with optional backup functionality
- **New Function**: `Get-CAPI2EventLogStatus` - Display comprehensive log status including enabled state, event count, size, and date ranges
- **New Function**: `Start-CAPI2Troubleshooting` - Interactive troubleshooting workflow that automates the entire diagnostic process
- **New Function**: `Stop-CAPI2Troubleshooting` - Complete troubleshooting sessions with export, cleanup, and logging management
- **Error Code Dictionary**: Built-in comprehensive error code mappings for common CAPI2 errors (CERT_E_UNTRUSTEDROOT, CERT_E_REVOCATION_FAILURE, etc.)
- **Convenient Aliases**: Added 5 short aliases (`Find-CertEvents`, `Get-CertChain`, `Enable-CapiLog`, `Disable-CapiLog`, `Clear-CapiLog`)
- **HTML Export**: Beautiful HTML reports with color-coded severity indicators and embedded error analysis
- **Cross-Platform Compatibility**: Support for both PowerShell Desktop and PowerShell Core editions
- **Enhanced Documentation**: Comprehensive inline help with detailed examples for all 11 functions
- **Test Suite**: Complete Pester test framework with integration tests (CAPI2Tools.Tests.ps1)

### Changed
- **Restructured Architecture**: Organized code into logical regions (Error Code Mappings, Helper Functions, Event Log Management, etc.)
- **Enhanced Error Handling**: Improved null checks and error messages throughout all functions
- **Better User Feedback**: Color-coded console output with severity-based formatting (Error=Red, Warning=Yellow, Info=Cyan)
- **Improved Performance**: Optimized event log queries and XML parsing
- **Module Metadata**: Enhanced manifest with proper tags, license URI, project URI, and release notes
- **Parameter Validation**: Stronger parameter sets and validation for better usability
- **Verbose Logging**: Added comprehensive verbose output for troubleshooting and debugging

### Fixed
- **Array Indexing Error**: Fixed "Cannot index into a null array" issue in `Get-CAPI2EventLogStatus` when event log is empty
- **Module Export**: Properly exported helper function `Get-CAPI2ErrorDetails` for external use
- **Error Code Recognition**: Added missing FBF error code (CERT_E_CHAINING) to dictionary
- **HTML Export Encoding**: Improved HTML entity encoding for special characters in event data
- **Backup File Handling**: Better error handling for backup file creation in `Clear-CAPI2EventLog`

### Deprecated
- None - fully backward compatible with v2.0.0

---

## [2.0.0] - 2025-12-09

### Added
- **New Function**: `Find-CapiEventsByName` - Search CAPI2 events by DNS name or certificate subject without needing TaskID
- Automatic correlation discovery based on certificate names
- Support for wildcard pattern matching in certificate searches
- Time range filtering with configurable hours lookback
- Additional pattern filtering with `IncludePattern` parameter
- Color-coded console output for better user experience
- Comprehensive error handling and user-friendly warnings
- Grouped results showing TaskID, timestamp, event count, and full event details
- Export module members for proper PowerShell module usage
- Detailed inline documentation with multiple examples

### Changed
- Enhanced `Get-CapiTaskIDEvents` function documentation with clearer examples
- Improved script header metadata with tags, license URI, and project URI
- Updated copyright information to GNU GPL v3
- Restructured function order for better logical flow
- Enhanced verbose logging throughout all functions

### Removed
- Deprecated `Search-InUserData` function (replaced by `Find-CapiEventsByName`)
- Commented-out example code at end of script

### Fixed
- Better handling of empty result sets
- Improved error messages with actionable suggestions
- More robust XML parsing for event data

---

## [1.0.0] - 2022

### Added
- Initial release
- `Get-CapiTaskIDEvents` function for TaskID-based correlation
- `Convert-EventLogRecord` helper function for event parsing
- `Format-XML` helper function for XML formatting
- Basic error handling and parameter validation
- Support for all major CAPI2 event types

### Features
- Query CAPI2 events by correlation TaskID
- Parse and format event XML data
- Sort events chronologically by sequence number
- Output formatted event details including certificates, revocation info, and chain building

---

## Future Enhancements

### Planned for v2.1
- [ ] Export functionality to multiple formats (JSON, XML, HTML)
- [ ] Performance optimization for large event logs
- [ ] Real-time monitoring mode
- [ ] Event filtering by application/process name
- [ ] Statistical analysis of certificate chains
- [ ] Integration with PowerShell transcript logging

### Under Consideration
- [ ] GUI interface using Windows Forms or WPF
- [ ] Remote computer support via PowerShell remoting
- [ ] Scheduled event collection and reporting
- [ ] Integration with centralized logging systems
- [ ] Email alerting for specific error patterns
- [ ] Certificate expiration tracking

---

[2.5.0]: https://github.com/BetaHydri/GetCapiCorrelationTask/releases/tag/v2.5.0
[2.0.0]: https://github.com/BetaHydri/GetCapiCorrelationTask/releases/tag/v2.0.0
[1.0.0]: https://github.com/BetaHydri/GetCapiCorrelationTask/releases/tag/v1.0.0
