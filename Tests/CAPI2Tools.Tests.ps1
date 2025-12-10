<#
.SYNOPSIS
    Pester tests for CAPI2Tools PowerShell module (Compatible with Pester v3+)
    
.DESCRIPTION
    Comprehensive test suite for validating CAPI2Tools module functionality.
    Tests include unit tests, integration tests, and validation of helper functions.
    Updated for v2.9 to include tests for multi-file export and Format parameter.
    
.NOTES
    Version:        1.3
    Author:         Jan Tiedemann
    Creation Date:  December 2025
    Last Updated:   December 2025 (v2.9 multi-file export tests added)
    Pester Version: 3.x compatible
    
.EXAMPLE
    Invoke-Pester -Path .\Tests\CAPI2Tools.Tests.ps1
#>

# Import the module before tests
$ModulePath = Join-Path $PSScriptRoot '..\CAPI2Tools.psm1'
Import-Module $ModulePath -Force

Describe "CAPI2Tools Module" {
    
    Context "Module Import and Structure" {
        
        It "Should import the module successfully" {
            Get-Module CAPI2Tools | Should Not BeNullOrEmpty
        }
        
        It "Should have the correct module version" {
            $Module = Get-Module CAPI2Tools
            $Module.Version | Should Not BeNullOrEmpty
        }
        
        It "Should export Find-CapiEventsByName function" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Find-CapiEventsByName' | Should Be $true
        }
        
        It "Should export Get-CapiTaskIDEvents function" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Get-CapiTaskIDEvents' | Should Be $true
        }
        
        It "Should export Enable-CAPI2EventLog function" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Enable-CAPI2EventLog' | Should Be $true
        }
        
        It "Should export Get-CapiErrorAnalysis function" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Get-CapiErrorAnalysis' | Should Be $true
        }
        
        It "Should export Export-CapiEvents function" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Export-CapiEvents' | Should Be $true
        }
        
        It "Should export Get-CapiCertificateReport function (v2.6 simplified workflow)" {
            $ExportedCommands = (Get-Module CAPI2Tools).ExportedFunctions.Keys
            $ExportedCommands -contains 'Get-CapiCertificateReport' | Should Be $true
        }
        
        It "Should export Find-CertEvents alias" {
            $ExportedAliases = (Get-Module CAPI2Tools).ExportedAliases.Keys
            $ExportedAliases -contains 'Find-CertEvents' | Should Be $true
        }
    }
    
    Context "Error Code Mappings" {
        
        It "Should return error details for known error code (0x80092013)" {
            $Result = Get-CAPI2ErrorDetails -ErrorCode '0x80092013'
            $Result | Should Not BeNullOrEmpty
            $Result.HexCode | Should Be 'CRYPT_E_REVOCATION_OFFLINE'
            $Result.Severity | Should Be 'Warning'
        }
        
        It "Should return error details for CERT_E_EXPIRED" {
            $Result = Get-CAPI2ErrorDetails -ErrorCode '0x800B0101'
            $Result | Should Not BeNullOrEmpty
            $Result.HexCode | Should Be 'CERT_E_EXPIRED'
            $Result.Description | Should Match 'validity period'
        }
        
        It "Should handle FBF error code" {
            $Result = Get-CAPI2ErrorDetails -ErrorCode 'FBF'
            $Result | Should Not BeNullOrEmpty
            $Result.HexCode | Should Be 'CERT_E_CHAINING'
        }
        
        It "Should return UNKNOWN for unrecognized error codes" {
            $Result = Get-CAPI2ErrorDetails -ErrorCode '0xDEADBEEF'
            $Result | Should Not BeNullOrEmpty
            $Result.HexCode | Should Be 'UNKNOWN'
            $Result.Description | Should Match 'Unknown'
        }
        
        It "Should include all required error detail properties" {
            $Result = Get-CAPI2ErrorDetails -ErrorCode '0x80092013'
            $Result.Code | Should Not BeNullOrEmpty
            $Result.HexCode | Should Not BeNullOrEmpty
            $Result.Description | Should Not BeNullOrEmpty
            $Result.CommonCause | Should Not BeNullOrEmpty
            $Result.Resolution | Should Not BeNullOrEmpty
            $Result.Severity | Should Not BeNullOrEmpty
        }
    }
    
    Context "Display Character Helper Functions (Internal)" {
        
        # Note: Get-DisplayChar is an internal helper function not exported
        # These tests verify the function exists in the module scope
        
        It "Should have Get-DisplayChar function defined in module" {
            $ModuleFunctions = (Get-Module CAPI2Tools).Invoke({ Get-Command -Type Function -name Get-DisplayChar -ErrorAction SilentlyContinue })
            $ModuleFunctions | Should Not BeNullOrEmpty
        }
        
        It "Should have Write-BoxHeader function defined in module" {
            $ModuleFunctions = (Get-Module CAPI2Tools).Invoke({ Get-Command -Type Function -name Write-BoxHeader -ErrorAction SilentlyContinue })
            $ModuleFunctions | Should Not BeNullOrEmpty
        }
    }
    
    Context "Export-CapiEvents Function" {
        
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
        
        It "Should export to CSV format" {
            $CsvPath = "$script:TestExportPath.csv"
            Export-CapiEvents -Events $script:MockEvents -Path $CsvPath -Format CSV
            
            Test-Path $CsvPath | Should Be $true
            $CsvContent = @(Import-Csv $CsvPath)
            $CsvContent.Count | Should BeGreaterThan 0
            
            Remove-Item $CsvPath -Force -ErrorAction SilentlyContinue
        }
        
        It "Should export to JSON format" {
            $JsonPath = "$script:TestExportPath.json"
            Export-CapiEvents -Events $script:MockEvents -Path $JsonPath -Format JSON
            
            Test-Path $JsonPath | Should Be $true
            $JsonContent = Get-Content $JsonPath -Raw | ConvertFrom-Json
            $JsonContent.Events | Should Not BeNullOrEmpty
            
            Remove-Item $JsonPath -Force -ErrorAction SilentlyContinue
        }
        
        It "Should export to HTML format" {
            $HtmlPath = "$script:TestExportPath.html"
            Export-CapiEvents -Events $script:MockEvents -Path $HtmlPath -Format HTML
            
            Test-Path $HtmlPath | Should Be $true
            $HtmlContent = Get-Content $HtmlPath -Raw
            $HtmlContent | Should Match '<html>'
            $HtmlContent | Should Match 'CAPI2'
            
            Remove-Item $HtmlPath -Force -ErrorAction SilentlyContinue
        }
        
        It "Should include certificate name in HTML export header" {
            $HtmlPath = "$script:TestExportPath.cert_header.html"
            Export-CapiEvents -Events $script:MockEvents -Path $HtmlPath -Format HTML
            
            $HtmlContent = Get-Content $HtmlPath -Raw
            $HtmlContent | Should Match 'cert-name'
            $HtmlContent | Should Match 'Certificate:'
            
            Remove-Item $HtmlPath -Force -ErrorAction SilentlyContinue
        }
    }
    
    Context "Get-CapiErrorAnalysis Function" {
        
        It "Should accept Events parameter" {
            $Function = Get-Command Get-CapiErrorAnalysis
            $Function.Parameters.ContainsKey('Events') | Should Be $true
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
            $Result | Should BeNullOrEmpty
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
            $Result | Should BeNullOrEmpty
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
            $Result | Should Not BeNullOrEmpty
            $Result[0].ErrorCode | Should Be '0x800B0101'
            $Result[0].ErrorName | Should Be 'CERT_E_EXPIRED'
        }
    }
    
    Context "Format-XML Function" {
        
        It "Should format XML with default indentation" {
            [xml]$TestXml = '<root><child>value</child></root>'
            $Result = Format-XML -Xml $TestXml
            
            $Result | Should Not BeNullOrEmpty
            $Result | Should Match 'root'
            $Result | Should Match 'child'
        }
    }
    
    Context "Find-CapiEventsByName Function" {
        
        It "Should have Name parameter" {
            $Function = Get-Command Find-CapiEventsByName
            $Function.Parameters.ContainsKey('Name') | Should Be $true
        }
        
        It "Should have MaxEvents parameter" {
            $Function = Get-Command Find-CapiEventsByName
            $Function.Parameters.ContainsKey('MaxEvents') | Should Be $true
        }
        
        It "Should have Hours parameter" {
            $Function = Get-Command Find-CapiEventsByName
            $Function.Parameters.ContainsKey('Hours') | Should Be $true
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
            $Function | Should Not BeNullOrEmpty
        }
        
        It "Should have updated help documentation mentioning SubjectAltName and ProcessName" {
            $Help = Get-Help Find-CapiEventsByName -Full
            $HelpText = $Help.Description.Text + $Help.examples.example.code -join ' '
            # Should mention at least one of the new search capabilities
            ($HelpText -match 'SubjectAltName|ProcessName|CN|chrome\.exe|outlook\.exe') | Should Be $true
        }
    }
    
    Context "Get-CapiTaskIDEvents Function" {
        
        It "Should have TaskID parameter" {
            $Function = Get-Command Get-CapiTaskIDEvents
            $Function.Parameters.ContainsKey('TaskID') | Should Be $true
        }
    }
    
    Context "Get-CapiCertificateReport Function (v2.9 Multi-File Export)" {
        
        It "Should have Name parameter" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters.ContainsKey('Name') | Should Be $true
        }
        
        It "Should have ExportPath parameter" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters.ContainsKey('ExportPath') | Should Be $true
        }
        
        It "Should have Format parameter with ValidateSet (v2.9 feature)" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters.ContainsKey('Format') | Should Be $true
            
            # Check if it has ValidateSet attribute
            $ValidateSetAttr = $Function.Parameters['Format'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $ValidateSetAttr | Should Not BeNullOrEmpty
            
            # Check valid values
            $ValidateSetAttr.ValidValues -contains 'HTML' | Should Be $true
            $ValidateSetAttr.ValidValues -contains 'JSON' | Should Be $true
            $ValidateSetAttr.ValidValues -contains 'CSV' | Should Be $true
            $ValidateSetAttr.ValidValues -contains 'XML' | Should Be $true
        }
        
        It "Format parameter should default to HTML" {
            $Function = Get-Command Get-CapiCertificateReport
            $DefaultValue = $Function.Parameters['Format'].Attributes | Where-Object { $_.TypeId.Name -eq 'PSDefaultValueAttribute' }
            # Default is set in param block, check via Get-Help
            $Help = Get-Help Get-CapiCertificateReport -Parameter Format
            $Help.defaultValue | Should Be 'HTML'
        }
        
        It "Should have Hours parameter with default value" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters.ContainsKey('Hours') | Should Be $true
        }
        
        It "Should have ShowDetails switch parameter" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters.ContainsKey('ShowDetails') | Should Be $true
            $Function.Parameters['ShowDetails'].SwitchParameter | Should Be $true
        }
        
        It "Should have OpenReport switch parameter" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters.ContainsKey('OpenReport') | Should Be $true
            $Function.Parameters['OpenReport'].SwitchParameter | Should Be $true
        }
        
        It "ExportPath parameter help should indicate directory path (v2.9 change)" {
            $Help = Get-Help Get-CapiCertificateReport -Parameter ExportPath
            $Help.description.Text | Should Match 'directory|Directory|folder'
        }
        
        It "Should accept Name as positional parameter" {
            $Function = Get-Command Get-CapiCertificateReport
            $Function.Parameters['Name'].Attributes.Position | Should Be 0
        }
    }
    
    Context "Error Handling" {
        
        It "Get-CAPI2ErrorDetails should not throw on invalid input" {
            { Get-CAPI2ErrorDetails -ErrorCode 'InvalidCode123' } | Should Not Throw
            { Get-CAPI2ErrorDetails -ErrorCode '0xFFFFFFFF' } | Should Not Throw
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
            
            { Export-CapiEvents -Events $MockEvents -Path $TempPath } | Should Not Throw
            
            Test-Path $TempPath | Should Be $true
            
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
            
            { Get-CapiErrorAnalysis -Events $MockErrorEvents } | Should Not Throw
        }
    }
    
    Context "Multi-File Export Tests (v2.9 Get-CapiCertificateReport)" {
        
        It "Should not throw when no events are found" {
            # This simulates the scenario where certificate name doesn't exist in logs
            # Use Hours 0.01 (36 seconds) to speed up the test
            { Get-CapiCertificateReport -Name "nonexistent-test-certificate-$(Get-Date -Format 'yyyyMMddHHmmss').com" -Hours 0.01 -ErrorAction SilentlyContinue } | Should Not Throw
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
            Get-CapiCertificateReport -Name "test-autocreate-$(Get-Date -Format 'yyyyMMddHHmmss').com" -ExportPath $TempDir -Format HTML -Hours 0.01 -ErrorAction SilentlyContinue
            
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
            
            # Should throw error when ExportPath is a file
            { Get-CapiCertificateReport -Name "test.com" -ExportPath $TempFile -Format HTML -ErrorAction Stop } | Should -Throw
            
            # Clean up
            Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
        }
        
        It "Should accept Format parameter with HTML value" {
            $TempDir = Join-Path $env:TEMP "cert_html_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            { Get-CapiCertificateReport -Name "test-html.com" -ExportPath $TempDir -Format HTML -Hours 0.01 -ErrorAction SilentlyContinue } | Should Not Throw
            
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "Should accept Format parameter with JSON value" {
            $TempDir = Join-Path $env:TEMP "cert_json_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            { Get-CapiCertificateReport -Name "test-json.com" -ExportPath $TempDir -Format JSON -Hours 0.01 -ErrorAction SilentlyContinue } | Should Not Throw
            
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "Should accept Format parameter with CSV value" {
            $TempDir = Join-Path $env:TEMP "cert_csv_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            { Get-CapiCertificateReport -Name "test-csv.com" -ExportPath $TempDir -Format CSV -Hours 0.01 -ErrorAction SilentlyContinue } | Should Not Throw
            
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "Should accept Format parameter with XML value" {
            $TempDir = Join-Path $env:TEMP "cert_xml_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            { Get-CapiCertificateReport -Name "test-xml.com" -ExportPath $TempDir -Format XML -Hours 0.01 -ErrorAction SilentlyContinue } | Should Not Throw
            
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "Format parameter should reject invalid values" {
            $TempDir = Join-Path $env:TEMP "cert_invalid_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            # Should throw because 'TXT' is not in ValidateSet
            { Get-CapiCertificateReport -Name "test.com" -ExportPath $TempDir -Format "TXT" -ErrorAction Stop } | Should -Throw
            
            if (Test-Path $TempDir) {
                Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "Should accept Hours parameter" {
            { Get-CapiCertificateReport -Name "test-hours.com" -Hours 0.01 -ErrorAction SilentlyContinue } | Should Not Throw
        }
        
        It "Should accept ShowDetails switch" {
            { Get-CapiCertificateReport -Name "test-details.com" -ShowDetails -Hours 0.01 -ErrorAction SilentlyContinue } | Should Not Throw
        }
        
        It "Should accept all parameters together" {
            $TempDir = Join-Path $env:TEMP "cert_full_test_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            { Get-CapiCertificateReport -Name "test-all-params.com" -ExportPath $TempDir -Format HTML -Hours 1 -ShowDetails -Hours 0.01 -ErrorAction SilentlyContinue } | Should Not Throw
            
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
            Get-CapiCertificateReport -Name "test-autocreate.com" -ExportPath $TempDir -Format HTML -ErrorAction SilentlyContinue | Out-Null
            
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
            
            # This should throw an error (remove SilentlyContinue to allow error to propagate)
            { Get-CapiCertificateReport -Name "test-file-path.com" -ExportPath $TempFile -Format HTML -ErrorAction Stop 2>&1 } | Should -Throw
            
            # Cleanup
            Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
        }
        
        It "Should reject invalid Format values" {
            # This should throw a parameter validation error because 'PDF' is not in ValidateSet
            { Get-CapiCertificateReport -Name "test.com" -ExportPath "C:\\temp" -Format "PDF" 2>&1 } | Should -Throw
        }
    }
}
