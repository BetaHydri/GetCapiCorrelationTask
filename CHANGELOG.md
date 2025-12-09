# Changelog

All notable changes to the CAPI2 Event Log Correlation Toolkit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[2.0.0]: https://github.com/BetaHydri/GetCapiCorrelationTask/releases/tag/v2.0.0
[1.0.0]: https://github.com/BetaHydri/GetCapiCorrelationTask/releases/tag/v1.0.0
