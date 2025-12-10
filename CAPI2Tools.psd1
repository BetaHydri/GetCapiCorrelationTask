@{
    # Script module or binary module file associated with this manifest.
    RootModule           = 'CAPI2Tools.psm1'
    
    # Version number of this module.
    ModuleVersion        = '2.8.0'
    
    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')
    
    # ID used to uniquely identify this module
    GUID                 = '3228f1cd-8cca-4839-b9aa-7c93c83a917e'
    
    # Author of this module
    Author               = 'Jan Tiedemann'
    
    # Company or vendor of this module
    CompanyName          = 'Jan Tiedemann'
    
    # Copyright statement for this module
    Copyright            = '(c) 2022-2025 Jan Tiedemann. All rights reserved. Licensed under GNU GPL v3.'
    
    # Description of the functionality provided by this module
    Description          = @'
CAPI2 Event Log Correlation Analysis Toolkit - A comprehensive PowerShell module for analyzing Windows 
certificate validation chains, troubleshooting TLS/SSL connections, and diagnosing CAPI2 cryptographic errors.

Features:
- Simplified one-command workflow with Get-CapiCertificateReport (NEW in v2.6)
- Automatic certificate chain discovery by DNS/certificate name
- Intelligent error analysis with human-readable descriptions
- Event log management (enable, disable, clear, status)
- Export functionality (CSV, JSON, HTML, XML)
- Before/after comparison for tracking fix progress
- Built-in error code dictionary with resolution steps
'@
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion    = '5.1'
    
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport    = @(
        # Simplified Workflow (Recommended)
        'Get-CapiCertificateReport',
        
        # Search and Retrieval
        'Find-CapiEventsByName',
        'Get-CapiTaskIDEvents',
        
        # Analysis
        'Get-CapiErrorAnalysis',
        
        # Export
        'Export-CapiEvents',
        
        # Comparison
        'Compare-CapiEvents',
        
        # Event Log Management
        'Enable-CAPI2EventLog',
        'Disable-CAPI2EventLog',
        'Clear-CAPI2EventLog',
        'Get-CAPI2EventLogStatus',
        
        # Workflow Helpers
        'Start-CAPI2Troubleshooting',
        'Stop-CAPI2Troubleshooting'
    )
    
    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport      = @()
    
    # Variables to export from this module
    VariablesToExport    = @()
    
    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport      = @(
        'Find-CertEvents',
        'Get-CertChain',
        'Enable-CapiLog',
        'Disable-CapiLog',
        'Clear-CapiLog'
    )
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData          = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @('CAPI2', 'Certificate', 'TLS', 'SSL', 'Troubleshooting', 'PKI', 'EventLog', 'Security', 'Windows')
            
            # A URL to the license for this module.
            LicenseUri   = 'https://www.gnu.org/licenses/gpl-3.0.en.html'
            
            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/BetaHydri/GetCapiCorrelationTask'
            
            # ReleaseNotes of this module
            ReleaseNotes = @'
## Version 2.5.0 (December 2025)

### New Features
- Converted to PowerShell module (.psm1/.psd1)
- Added workflow cmdlets: Start-CAPI2Troubleshooting, Stop-CAPI2Troubleshooting
- Comprehensive error analysis with resolution guidance
- Multi-format export (CSV, JSON, HTML, XML)
- Before/after comparison for tracking fixes
- CAPI2 event log management cmdlets

### Improvements
- Enhanced parameter sets for better usability
- Improved error handling and user feedback
- Color-coded console output
- Built-in error code dictionary

### Breaking Changes
- None - backward compatible with v2.0

## Version 2.0.0
- Added DNS/certificate name search
- Enhanced UI and documentation

## Version 1.0.0
- Initial release
'@
            # Prerelease string of this module
            # Prerelease = ''
            
            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false
            
            # External dependent modules of this module
            # ExternalModuleDependencies = @()
        }
    }
    
    # HelpInfo URI of this module
    HelpInfoURI          = 'https://github.com/BetaHydri/GetCapiCorrelationTask/blob/master/README.md'
}
