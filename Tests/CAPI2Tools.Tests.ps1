<#
.SYNOPSIS
    Pester tests for CAPI2Tools PowerShell module (Compatible with Pester v3+)
    
.DESCRIPTION
    Comprehensive test suite for validating CAPI2Tools module functionality.
    Tests include unit tests, integration tests, and validation of helper functions.
    
.NOTES
    Version:        1.0
    Author:         Jan Tiedemann
    Creation Date:  December 2025
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
            $ModuleFunctions = (Get-Module CAPI2Tools).Invoke({ Get-Command -Type Function -Name Get-DisplayChar -ErrorAction SilentlyContinue })
            $ModuleFunctions | Should Not BeNullOrEmpty
        }
        
        It "Should have Write-BoxHeader function defined in module" {
            $ModuleFunctions = (Get-Module CAPI2Tools).Invoke({ Get-Command -Type Function -Name Write-BoxHeader -ErrorAction SilentlyContinue })
            $ModuleFunctions | Should Not BeNullOrEmpty
        }
    }
    
    Context "Export-CapiEvents Function" {
        
        # Create mock event data once for all tests
        $script:MockEvents = @(
            [PSCustomObject]@{
                TimeCreated = Get-Date
                ID = 11
                RecordType = 'Information'
                DetailedMessage = '<CertGetCertificateChain xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Certificate subjectName="CN=test.com" /></CertGetCertificateChain>'
            }
        )
        
        $script:TestExportPath = Join-Path $env:TEMP "CAPI2_Test_Export_$(Get-Date -Format 'yyyyMMddHHmmss')"
        
        It "Should export to CSV format" {
            $CsvPath = "$script:TestExportPath.csv"
            Export-CapiEvents -Events $script:MockEvents -Path $CsvPath -Format CSV
            
            Test-Path $CsvPath | Should Be $true
            $CsvContent = Import-Csv $CsvPath
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
                    TimeCreated = Get-Date
                    ID = 11
                    DetailedMessage = '<Result value="0"/>'
                }
            )
            
            $Result = Get-CapiErrorAnalysis -Events $MockGoodEvents
            $Result | Should BeNullOrEmpty
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
    }
    
    Context "Get-CapiTaskIDEvents Function" {
        
        It "Should have TaskID parameter" {
            $Function = Get-Command Get-CapiTaskIDEvents
            $Function.Parameters.ContainsKey('TaskID') | Should Be $true
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
                    TimeCreated = Get-Date
                    ID = 11
                    RecordType = 'Information'
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
                    TimeCreated = Get-Date
                    ID = 30
                    RecordType = 'Error'
                    DetailedMessage = '<Result value="0x800B0101"/>'
                }
            )
            
            { Get-CapiErrorAnalysis -Events $MockErrorEvents } | Should Not Throw
        }
    }
}
