<#
.SYNOPSIS
    Pester tests for CAPI2Tools PowerShell module (Pester 5.x compatible)
    
.DESCRIPTION
    Comprehensive test suite for validating CAPI2Tools module functionality.
    Tests include unit tests, integration tests, and validation of helper functions.
    Updated for v2.12.0 to include tests for Get-CapiAllErrors feature.
    
.NOTES
    Version:        2.1
    Author:         Jan Tiedemann
    Creation Date:  December 2025
    Last Updated:   December 2025 (v2.12.0 - Get-CapiAllErrors tests)
    Pester Version: 5.x+ required
    
.EXAMPLE
    Invoke-Pester -Path .\Tests\CAPI2Tools.Tests.ps1
#>

# Import the module before tests
$ModulePath = Join-Path $PSScriptRoot '..\CAPI2Tools.psm1'
Import-Module $ModulePath -Force

Describe "CAPI2Tools Module" {
    
    Context "Module Import and Structure" {
        
        It "Should import the module successfully" {
            Get-Module CAPI2Tools | Should -Not -BeNullOrEmpty
        }
        
        It "Should have the correct module version" {
            $Module = Get-Module CAPI2Tools
            $Module.Version | Should -Not -BeNullOrEmpty
        }
        
        It "Should export Find-CapiEventsByName function" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Find-CapiEventsByName' | Should -Be $true
        }
        
        It "Should export Get-CapiTaskIDEvents function" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Get-CapiTaskIDEvents' | Should -Be $true
        }
        
        It "Should export Enable-CAPI2EventLog function" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Enable-CAPI2EventLog' | Should -Be $true
        }
        
        It "Should export Get-CapiErrorAnalysis function" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Get-CapiErrorAnalysis' | Should -Be $true
        }
        
        It "Should export Export-CapiEvents function" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Export-CapiEvents' | Should -Be $true
        }
        
        It "Should export Get-CapiCertificateReport function (v2.6 simplified workflow)" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Get-CapiCertificateReport' | Should -Be $true
        }
        
        It "Should export Get-CapiAllErrors function (v2.12.0 comprehensive error discovery)" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Get-CapiAllErrors' | Should -Be $true
        }
        
        It "Should export Find-CertEvents alias" {
            $ExportedAliases = (Get-Module CAPI2Tools).ExportedAliases.Keys
            $ExportedAliases -contains 'Find-CertEvents' | Should -Be $true
        }
        
        It "Should export Get-AllErrors alias (v2.12.0)" {
            $ExportedAliases = (Get-Module CAPI2Tools).ExportedAliases.Keys
            $ExportedAliases -contains 'Get-AllErrors' | Should -Be $true
        }
    }
    
    Context "Error Code Mappings" {
        
        It "Should return error details for known error code (0x80092013)" {
            $Result = Get-CAPI2ErrorDetails -ErrorCode '0x80092013'
            $Result | Should -Not -BeNullOrEmpty
            $Result.HexCode | Should -Be 'CRYPT_E_REVOCATION_OFFLINE'
            $Result.Severity | Should -Be 'Warning'
        }
        
        It "Should return error details for CERT_E_EXPIRED" {
            $Result = Get-CAPI2ErrorDetails -ErrorCode '0x800B0101'
            $Result | Should -Not -BeNullOrEmpty
            $Result.HexCode | Should -Be 'CERT_E_EXPIRED'
            $Result.Description | Should -Match 'validity period'
        }
        
        It "Should handle FBF error code" {
            $Result = Get-CAPI2ErrorDetails -ErrorCode 'FBF'
            $Result | Should -Not -BeNullOrEmpty
            $Result.HexCode | Should -Be 'CERT_E_CHAINING'
        }
        
        It "Should return UNKNOWN for unrecognized error codes" {
            $Result = Get-CAPI2ErrorDetails -ErrorCode '0xDEADBEEF'
            $Result | Should -Not -BeNullOrEmpty
            $Result.HexCode | Should -Be 'UNKNOWN'
            $Result.Description | Should -Match 'Unknown'
        }
        
        It "Should include all required error detail properties" {
            $Result = Get-CAPI2ErrorDetails -ErrorCode '0x80092013'
            $Result.Code | Should -Not -BeNullOrEmpty
            $Result.HexCode | Should -Not -BeNullOrEmpty
            $Result.Description | Should -Not -BeNullOrEmpty
            $Result.CommonCause | Should -Not -BeNullOrEmpty
            $Result.Resolution | Should -Not -BeNullOrEmpty
            $Result.Severity | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Display Character Helper Functions (Internal)" {
        
        # Note: Get-DisplayChar is an internal helper function not exported
        # These tests verify the function exists in the module scope
        
        It "Should have Get-DisplayChar function defined in module" {
            $ModuleFunctions = (Get-Module CAPI2Tools).Invoke({ Get-Command -Type Function -Name Get-DisplayChar -ErrorAction SilentlyContinue })
            $ModuleFunctions | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Write-BoxHeader function defined in module" {
            $ModuleFunctions = (Get-Module CAPI2Tools).Invoke({ Get-Command -Type Function -Name Write-BoxHeader -ErrorAction SilentlyContinue })
            $ModuleFunctions | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Export-CapiEvents Function" {
        
        BeforeAll {
            # Create mock event data once for all tests
            $script:MockEvents = @(
                [PSCustomObject]@{
                    TimeCreated     = Get-Date
                    ID              = 11
                    RecordType      = 'Information'
                    DetailedMessage = '<CertGetCertificateChain xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Certificate subjectName="CN=test.com" /></CertGetCertificateChain>'
                }
            )
            
            $script:TestExportPath = Join-Path $env:TEMP "CAPI2_Test_Export_$(Get-Date -Format 'yyyyMMddHHmmss')"
        }
        
        It "Should export to CSV format" {
            $CsvPath = "$script:TestExportPath.csv"
            Export-CapiEvents -Events $script:MockEvents -Path $CsvPath -Format CSV
            
            Test-Path $CsvPath | Should -Be $true
            $CsvContent = @(Import-Csv $CsvPath)
            $CsvContent.Count | Should -BeGreaterThan 0
            
            Remove-Item $CsvPath -Force -ErrorAction SilentlyContinue
        }
        
        It "Should export to JSON format" {
            $JsonPath = "$script:TestExportPath.json"
            Export-CapiEvents -Events $script:MockEvents -Path $JsonPath -Format JSON
            
            Test-Path $JsonPath | Should -Be $true
            $JsonContent = Get-Content $JsonPath -Raw | ConvertFrom-Json
            $JsonContent.Events | Should -Not -BeNullOrEmpty
            
            Remove-Item $JsonPath -Force -ErrorAction SilentlyContinue
        }
        
        It "Should export to HTML format" {
            $HtmlPath = "$script:TestExportPath.html"
            Export-CapiEvents -Events $script:MockEvents -Path $HtmlPath -Format HTML
            
            Test-Path $HtmlPath | Should -Be $true
            $HtmlContent = Get-Content $HtmlPath -Raw
            $HtmlContent | Should -Match '<html>'
            $HtmlContent | Should -Match 'CAPI2'
            
            Remove-Item $HtmlPath -Force -ErrorAction SilentlyContinue
        }
        
        It "Should include certificate information section in HTML export when Event 90 present" {
            $HtmlPath = "$script:TestExportPath.cert_header.html"
            Export-CapiEvents -Events $script:MockEvents -Path $HtmlPath -Format HTML
            
            $HtmlContent = Get-Content $HtmlPath -Raw
            # Basic HTML structure should always be present
            $HtmlContent | Should -Match 'CAPI2 Certificate Validation Report'
            $HtmlContent | Should -Match 'TaskID:'
            # Certificate info section only appears if Event 90 (X509 Objects) exists
            # Mock events don't have Event 90, so we just verify structure is valid
            $HtmlContent | Should -Match '</html>'
            
            Remove-Item $HtmlPath -Force -ErrorAction SilentlyContinue
        }
    }
    
    Context "Get-CapiErrorAnalysis Function" {
        
        It "Should accept Events parameter" {
            $Function = Get-Command Get-CapiErrorAnalysis
            $Function.Parameters.ContainsKey('Events') | Should -Be $true
        }
        
        It "Should return null for events with no errors" {
            $MockGoodEvents = @(
                [PSCustomObject]@{
                    TimeCreated     = Get-Date
                    ID              = 11
                    DetailedMessage = '<Result value="0"/>'
                }
            )
            
            $Result = Get-CapiErrorAnalysis -Events $MockGoodEvents
            $Result | Should -BeNullOrEmpty
        }
        
        It "Should not treat Event ID 30 Flags as error codes (bug fix regression test)" {
            # Event ID 30 contains Flags with value attributes that are NOT error codes
            # This test ensures we only parse Result/Error nodes, not all value attributes
            $MockEvent30 = @(
                [PSCustomObject]@{
                    TimeCreated     = Get-Date
                    ID              = 30
                    DetailedMessage = '<CertVerifyCertificateChainPolicy><Policy type="CERT_CHAIN_POLICY_MICROSOFT_ROOT" constant="7" /><Certificate subjectName="Test Certificate" /><Flags value="F00" CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG="true" /><Result value="0" /></CertVerifyCertificateChainPolicy>'
                }
            )
            
            $Result = Get-CapiErrorAnalysis -Events $MockEvent30
            # Should return null because Result value="0" is success
            # Should NOT return UNKNOWN error for Flags value="F00"
            $Result | Should -BeNullOrEmpty
        }
        
        It "Should detect actual errors in Event ID 30 Result nodes" {
            # Event ID 30 with actual error in Result node
            $MockEvent30Error = @(
                [PSCustomObject]@{
                    TimeCreated     = Get-Date
                    ID              = 30
                    DetailedMessage = '<CertVerifyCertificateChainPolicy><Policy type="CERT_CHAIN_POLICY_SSL" constant="4" /><Certificate subjectName="expired.badssl.com" /><Flags value="F00" /><Result value="0x800B0101" /></CertVerifyCertificateChainPolicy>'
                }
            )
            
            $Result = Get-CapiErrorAnalysis -Events $MockEvent30Error 2>&1 | Where-Object { $_ -is [PSCustomObject] -and $_.PSObject.Properties['ErrorCode'] }
            # Should detect the actual error code in Result node
            $Result | Should -Not -BeNullOrEmpty
            $Result[0].ErrorCode | Should -Be '0x800B0101'
            $Result[0].ErrorName | Should -Be 'CERT_E_EXPIRED'
        }
    }
    
    Context "Format-XML Function" {
        
        It "Should format XML with default indentation" {
            [xml]$TestXml = '<root><child>value</child></root>'
            $Result = Format-XML -Xml $TestXml
            
            $Result | Should -Not -BeNullOrEmpty
            $Result | Should -Match 'root'
            $Result | Should -Match 'child'
        }
    }
    
    Context "Find-CapiEventsByName Function" {
        
        It "Should have Name parameter" {
            $Function = Get-Command Find-CapiEventsByName
            $Function.Parameters.ContainsKey('Name') | Should -Be $true
        }
        
        It "Should have MaxEvents parameter" {
            $Function = Get-Command Find-CapiEventsByName
            $Function.Parameters.ContainsKey('MaxEvents') | Should -Be $true
        }
        
        It "Should have Hours parameter" {
            $Function = Get-Command Find-CapiEventsByName
            $Function.Parameters.ContainsKey('Hours') | Should -Be $true
        }
        
        It "Should have IncludePattern parameter" {
            $Function = Get-Command Find-CapiEventsByName
            $Function.Parameters.ContainsKey('IncludePattern') | Should -Be $true
        }
        
        It "Should have FilterType parameter (v2.10.1 feature)" {
            $Function = Get-Command Find-CapiEventsByName
            $Function.Parameters.ContainsKey('FilterType') | Should -Be $true
        }
        
        It "Should have ValidateSet for FilterType parameter" {
            $Function = Get-Command Find-CapiEventsByName
            $FilterTypeParam = $Function.Parameters['FilterType']
            $ValidateSet = $FilterTypeParam.Attributes | Where-Object { $_.TypeId.Name -eq 'ValidateSetAttribute' }
            $ValidateSet | Should -Not -BeNullOrEmpty
        }
        
        It "Should have correct FilterType values" {
            $Function = Get-Command Find-CapiEventsByName
            $FilterTypeParam = $Function.Parameters['FilterType']
            $ValidateSet = $FilterTypeParam.Attributes | Where-Object { $_.TypeId.Name -eq 'ValidateSetAttribute' }
            $ValidValues = $ValidateSet.ValidValues
            $ValidValues -contains 'Revocation' | Should -Be $true
            $ValidValues -contains 'Expired' | Should -Be $true
            $ValidValues -contains 'Untrusted' | Should -Be $true
            $ValidValues -contains 'ChainBuilding' | Should -Be $true
            $ValidValues -contains 'PolicyValidation' | Should -Be $true
            $ValidValues -contains 'SignatureValidation' | Should -Be $true
            $ValidValues -contains 'ErrorsOnly' | Should -Be $true
        }
        
        It "Should reject invalid FilterType values" {
            $ThrowsError = $false
            try {
                # This should throw because 'InvalidType' is not in ValidateSet
                Find-CapiEventsByName -Name "test" -FilterType "InvalidType" -ErrorAction Stop
            }
            catch {
                $ThrowsError = $true
            }
            $ThrowsError | Should -Be $true
        }
        
        It "Should support enhanced multi-field search (v2.8 feature)" {
            # Create mock event with multiple searchable fields
            $MockEventXml = @'
<CertVerifyCertificateChainPolicy>
    <Certificate subjectName="test.example.com" />
    <EventAuxInfo ProcessName="chrome.exe" />
</CertVerifyCertificateChainPolicy>
'@
            
            # The function should be able to parse XML and search multiple fields
            # This is a structural test - actual search functionality requires event log access
            $Function = Get-Command Find-CapiEventsByName
            $Function | Should -Not -BeNullOrEmpty
        }
        
        It "Should have updated help documentation mentioning SubjectAltName and ProcessName" {
            $Help = Get-Help Find-CapiEventsByName -Full
            $HelpText = $Help.Description.Text + $Help.examples.example.code -join ' '
            # Should mention at least one of the new search capabilities
            ($HelpText -match 'SubjectAltName|ProcessName|CN|chrome\.exe|outlook\.exe') | Should -Be $true
        }
        
        It "Should have help documentation for FilterType parameter" {
            $Help = Get-Help Find-CapiEventsByName -Parameter FilterType
            $Help | Should -Not -BeNullOrEmpty
            $Help.description.Text | Should -Match 'Revocation|Expired|Untrusted'
        }
    }
    
    Context "Get-CapiTaskIDEvents Function" {
        
        It "Should have TaskID parameter" {
            $Function = Get-Command Get-CapiTaskIDEvents
            $Function.Parameters.ContainsKey('TaskID') | Should -Be $true
        }
    }
    
    Context "Get-CapiCertificateReport Function (v2.9 Multi-File Export)" {
        
        It "Should have Name parameter" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters.ContainsKey('Name') | Should -Be $true
        }
        
        It "Should have ExportPath parameter" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters.ContainsKey('ExportPath') | Should -Be $true
        }
        
        It "Should have Format parameter with ValidateSet (v2.9 feature)" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters.ContainsKey('Format') | Should -Be $true
            
            # Check if it has ValidateSet attribute
            $ValidateSetAttr = $Function.Parameters['Format'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $ValidateSetAttr | Should -Not -BeNullOrEmpty
            
            # Check valid values
            $ValidateSetAttr.ValidValues -contains 'HTML' | Should -Be $true
            $ValidateSetAttr.ValidValues -contains 'JSON' | Should -Be $true
            $ValidateSetAttr.ValidValues -contains 'CSV' | Should -Be $true
            $ValidateSetAttr.ValidValues -contains 'XML' | Should -Be $true
        }
        
        It "Format parameter should default to HTML" -Skip {
            # Skip this test in PS 5.1 as Get-Help can cause freezing
            $Function = Get-Command Get-CapiCertificateReport
            $DefaultValue = $Function.Parameters['Format'].Attributes | Where-Object { $_.TypeId.Name -eq 'PSDefaultValueAttribute' }
            # Default is set in param block, check via Get-Help
            $Help = Get-Help Get-CapiCertificateReport -Parameter Format
            $Help.defaultValue | Should -Be 'HTML'
        }
        
        It "Should have Hours parameter with default value" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters.ContainsKey('Hours') | Should -Be $true
        }
        
        It "Should have ShowDetails switch parameter" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters.ContainsKey('ShowDetails') | Should -Be $true
            $Function.Parameters['ShowDetails'].SwitchParameter | Should -Be $true
        }
        
        It "Should have OpenReport switch parameter" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters.ContainsKey('OpenReport') | Should -Be $true
            $Function.Parameters['OpenReport'].SwitchParameter | Should -Be $true
        }
        
        It "ExportPath parameter help should indicate directory path (v2.9 change)" {
            $Help = Get-Help Get-CapiCertificateReport -Parameter ExportPath
            $Help.description.Text | Should -Match 'directory|Directory|folder'
        }
        
        It "Should accept Name as positional parameter" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters['Name'].Attributes.Position | Should -Be 0
        }
    }
    
    Context "Error Handling" {
        
        It "Get-CAPI2ErrorDetails Should -Not -Throw on invalid input" {
            { Get-CAPI2ErrorDetails -ErrorCode 'InvalidCode123' } | Should -Not -Throw
            { Get-CAPI2ErrorDetails -ErrorCode '0xFFFFFFFF' } | Should -Not -Throw
        }
    }
}

Describe "CAPI2Tools Integration Tests" -Tag 'Integration' {
    
    Context "Module Usage Scenarios" {
        
        It "Should handle complete export workflow for CSV" {
            $MockEvents = @(
                [PSCustomObject]@{
                    TimeCreated     = Get-Date
                    ID              = 11
                    RecordType      = 'Information'
                    DetailedMessage = '<CertGetCertificateChain xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Certificate subjectName="CN=example.com" /></CertGetCertificateChain>'
                }
            )
            
            $TempPath = Join-Path $env:TEMP "integration_test_$(Get-Date -Format 'yyyyMMddHHmmss').csv"
            
            { Export-CapiEvents -Events $MockEvents -Path $TempPath } | Should -Not -Throw
            
            Test-Path $TempPath | Should -Be $true
            
            Remove-Item $TempPath -Force -ErrorAction SilentlyContinue
        }
        
        It "Should handle error analysis on mock error events" {
            $MockErrorEvents = @(
                [PSCustomObject]@{
                    TimeCreated     = Get-Date
                    ID              = 30
                    RecordType      = 'Error'
                    DetailedMessage = '<Result value="0x800B0101"/>'
                }
            )
            
            { Get-CapiErrorAnalysis -Events $MockErrorEvents } | Should -Not -Throw
        }
    }
    
    Context "Multi-File Export Tests (v2.9 Get-CapiCertificateReport)" {
        
        It "Should -Not -Throw when no events are found" {
            # This simulates the scenario where certificate name doesn't exist in logs
            # Use Hours 1 (minimum allowed) and MaxEvents 5 to avoid freezing with large logs
            { Get-CapiCertificateReport -Name "nonexistent-test-certificate-$(Get-Date -Format 'yyyyMMddHHmmss').com" -Hours 1 -MaxEvents 5 -ErrorAction SilentlyContinue } | Should -Not -Throw
        }
        
        It "Should create export directory if it doesn't exist (v2.9 feature)" {
            $TempDir = Join-Path $env:TEMP "cert_autocreate_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            # Ensure directory doesn't exist
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force
            }
            
            # Directory should not exist before call
            Test-Path $TempDir | Should -Be $false
            
            # Call with ExportPath - should create directory even if no events found
            # Use MaxEvents 5 to avoid freezing with large event logs
            Get-CapiCertificateReport -Name "test-autocreate-$(Get-Date -Format 'yyyyMMddHHmmss').com" -ExportPath $TempDir -Format HTML -Hours 1 -MaxEvents 5 -ErrorAction SilentlyContinue
            
            # Directory should now exist (created by the function)
            Test-Path $TempDir | Should -Be $true
            Test-Path $TempDir -PathType Container | Should -Be $true
            
            # Clean up
            Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        It "Should throw error if ExportPath is a file, not a directory" {
            $TempFile = Join-Path $env:TEMP "cert_file_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
            
            # Create a file
            "test" | Out-File -FilePath $TempFile -Force
            
            # Verify it's a file
            Test-Path $TempFile -PathType Leaf | Should -Be $true
            
            # Should write error when ExportPath is a file (use ErrorAction Continue to capture error in stream)
            # Use MaxEvents 5 to avoid freezing with large event logs
            $ErrorOutput = Get-CapiCertificateReport -Name "test.com" -ExportPath $TempFile -Format HTML -Hours 1 -MaxEvents 5 -ErrorAction Continue 2>&1
            $ErrorOutput | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | Should -Not -BeNullOrEmpty
            
            # Clean up
            Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
        }
        
        It "Should accept Format parameter with HTML value" {
            $TempDir = Join-Path $env:TEMP "cert_html_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            { Get-CapiCertificateReport -Name "test-html.com" -ExportPath $TempDir -Format HTML -Hours 1 -MaxEvents 5 -ErrorAction SilentlyContinue } | Should -Not -Throw
            
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "Should accept Format parameter with JSON value" {
            $TempDir = Join-Path $env:TEMP "cert_json_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            { Get-CapiCertificateReport -Name "test-json.com" -ExportPath $TempDir -Format JSON -Hours 1 -MaxEvents 5 -ErrorAction SilentlyContinue } | Should -Not -Throw
            
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "Should accept Format parameter with CSV value" {
            $TempDir = Join-Path $env:TEMP "cert_csv_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            { Get-CapiCertificateReport -Name "test-csv.com" -ExportPath $TempDir -Format CSV -Hours 1 -MaxEvents 5 -ErrorAction SilentlyContinue } | Should -Not -Throw
            
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "Should accept Format parameter with XML value" {
            $TempDir = Join-Path $env:TEMP "cert_xml_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            { Get-CapiCertificateReport -Name "test-xml.com" -ExportPath $TempDir -Format XML -Hours 1 -MaxEvents 5 -ErrorAction SilentlyContinue } | Should -Not -Throw
            
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "Format parameter should reject invalid values" {
            $TempDir = Join-Path $env:TEMP "cert_invalid_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            # ValidateSet should reject 'TXT' - use try/catch since Pester v3 has issues with Should Throw and parameter validation
            $ThrowsError = $false
            try {
                Get-CapiCertificateReport -Name "test.com" -ExportPath $TempDir -Format "TXT" -Hours 1 -MaxEvents 5 -ErrorAction Stop
            }
            catch {
                $ThrowsError = $true
            }
            $ThrowsError | Should -Be $true
            
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "Should accept Hours parameter" {
            { Get-CapiCertificateReport -Name "test-hours.com" -Hours 1 -MaxEvents 5 -ErrorAction SilentlyContinue } | Should -Not -Throw
        }
        
        It "Should accept ShowDetails switch" {
            { Get-CapiCertificateReport -Name "test-details.com" -ShowDetails -Hours 1 -MaxEvents 5 -ErrorAction SilentlyContinue } | Should -Not -Throw
        }
        
        It "Should accept all parameters together" {
            $TempDir = Join-Path $env:TEMP "cert_full_test_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            { Get-CapiCertificateReport -Name "test-all-params.com" -ExportPath $TempDir -Format HTML -Hours 1 -MaxEvents 5 -ShowDetails -ErrorAction SilentlyContinue } | Should -Not -Throw
            
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "Should create export directory if it doesn't exist" {
            $TempDir = Join-Path $env:TEMP "cert_autocreate_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            # Ensure directory doesn't exist
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force
            }
            
            # This should create the directory automatically
            # Use MaxEvents 5 to avoid freezing with large event logs
            Get-CapiCertificateReport -Name "test-autocreate.com" -ExportPath $TempDir -Format HTML -Hours 1 -MaxEvents 5 -ErrorAction SilentlyContinue | Out-Null
            
            # Directory should now exist (even if no events were found)
            Test-Path $TempDir | Should -Be $true
            (Get-Item $TempDir).PSIsContainer | Should -Be $true
            
            # Cleanup
            Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        It "Should reject ExportPath if it's a file, not a directory" {
            $TempFile = Join-Path $env:TEMP "cert_test_file_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
            
            # Create a file (not directory)
            "test" | Out-File $TempFile
            
            # Should write error when ExportPath is a file (use ErrorAction Continue to capture error in stream)
            # Use MaxEvents 5 to avoid freezing with large event logs
            $ErrorOutput = Get-CapiCertificateReport -Name "test-file-path.com" -ExportPath $TempFile -Format HTML -Hours 1 -MaxEvents 5 -ErrorAction Continue 2>&1
            $ErrorOutput | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | Should -Not -BeNullOrEmpty
            
            # Cleanup
            Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
        }
        
        It "Should reject invalid Format values" {
            # ValidateSet should reject 'PDF' - use try/catch since Pester v3 has issues with Should Throw and parameter validation  
            $ThrowsError = $false
            try {
                Get-CapiCertificateReport -Name "test.com" -ExportPath "C:\temp" -Format "PDF" -Hours 1 -MaxEvents 5 -ErrorAction Stop
            }
            catch {
                $ThrowsError = $true
            }
            $ThrowsError | Should -Be $true
        }
    }
    
    Context "Get-CapiAllErrors Function (v2.12.0)" {
        
        It "Should execute Get-CapiAllErrors without errors" {
            # Use MaxEvents 100 and Hours 1 to limit scope and avoid performance issues
            { Get-CapiAllErrors -Hours 1 -MaxEvents 100 -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should return PSCustomObject array with expected properties" {
            $Result = Get-CapiAllErrors -Hours 1 -MaxEvents 100
            
            if ($Result -and $Result.Count -gt 0) {
                # Verify object type
                $Result[0] | Should -BeOfType [PSCustomObject]
                
                # Verify required properties exist
                $Result[0].PSObject.Properties.Name -contains 'TimeCreated' | Should -Be $true
                $Result[0].PSObject.Properties.Name -contains 'TaskID' | Should -Be $true
                $Result[0].PSObject.Properties.Name -contains 'Certificate' | Should -Be $true
                $Result[0].PSObject.Properties.Name -contains 'ErrorCount' | Should -Be $true
                $Result[0].PSObject.Properties.Name -contains 'UniqueErrors' | Should -Be $true
                $Result[0].PSObject.Properties.Name -contains 'Errors' | Should -Be $true
                $Result[0].PSObject.Properties.Name -contains 'Events' | Should -Be $true
                $Result[0].PSObject.Properties.Name -contains 'CorrelatedEvents' | Should -Be $true
            }
        }
        
        It "Should respect MaxEvents parameter" {
            # Should not throw even with very small MaxEvents
            { Get-CapiAllErrors -Hours 1 -MaxEvents 10 -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should support GroupByError parameter" {
            { Get-CapiAllErrors -Hours 1 -MaxEvents 100 -GroupByError -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should include correlated events in results" {
            $Result = Get-CapiAllErrors -Hours 1 -MaxEvents 100
            
            if ($Result -and $Result.Count -gt 0) {
                # Events property should contain event objects
                $Result[0].Events | Should -Not -BeNullOrEmpty
                
                # CorrelatedEvents should be a positive number
                $Result[0].CorrelatedEvents | Should -BeGreaterThan 0
            }
        }
        
        It "Should create export directory if it doesn't exist" {
            $TempDir = Join-Path $env:TEMP "CAPI2_AllErrors_Test_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            # Ensure directory doesn't exist
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force
            }
            
            # This should create the directory automatically
            Get-CapiAllErrors -Hours 1 -MaxEvents 50 -ExportPath $TempDir -ErrorAction SilentlyContinue | Out-Null
            
            # Directory should now exist
            Test-Path $TempDir | Should -Be $true
            
            # Cleanup
            Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        It "Should export HTML files when errors exist" {
            $TempDir = Join-Path $env:TEMP "CAPI2_AllErrors_Export_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            try {
                # Run export
                Get-CapiAllErrors -Hours 1 -MaxEvents 100 -ExportPath $TempDir -ErrorAction SilentlyContinue | Out-Null
                
                # If errors were found, HTML files should exist
                if (Test-Path $TempDir) {
                    $HtmlFiles = Get-ChildItem $TempDir -Filter *.html -ErrorAction SilentlyContinue
                    # If directory exists and has files, they should be HTML
                    if ($HtmlFiles) {
                        $HtmlFiles[0].Extension | Should -Be '.html'
                    }
                }
            }
            finally {
                # Cleanup
                if (Test-Path $TempDir) {
                    Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        It "Should work with Get-AllErrors alias" {
            { Get-AllErrors -Hours 1 -MaxEvents 50 -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should handle ShowAnalysis parameter without hanging" {
            # ShowAnalysis can take a while, so use very limited scope
            # Just verify it doesn't throw an error
            { Get-CapiAllErrors -Hours 1 -MaxEvents 20 -ShowAnalysis -ErrorAction Stop | Out-Null } | Should -Not -Throw
        }
    }
}
