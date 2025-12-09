# CAPI2Tools Test Suite

This directory contains Pester tests for the CAPI2Tools PowerShell module.

## Test Files

- **CAPI2Tools.Tests.ps1** - Main test suite covering all module functions

## Running Tests

### Prerequisites

Install Pester module (if not already installed):

```powershell
Install-Module -Name Pester -Force -SkipPublisherCheck
```

### Run All Tests

```powershell
# Run all tests with detailed output
Invoke-Pester -Path .\Tests\CAPI2Tools.Tests.ps1 -Output Detailed

# Run all tests (default output)
Invoke-Pester -Path .\Tests\CAPI2Tools.Tests.ps1
```

### Run Specific Tests

```powershell
# Run only unit tests (excludes integration tests)
Invoke-Pester -Path .\Tests\CAPI2Tools.Tests.ps1 -ExcludeTag Integration

# Run only integration tests
Invoke-Pester -Path .\Tests\CAPI2Tools.Tests.ps1 -Tag Integration
```

### Generate Test Coverage Report

```powershell
# Run tests with code coverage analysis
$Config = New-PesterConfiguration
$Config.Run.Path = '.\Tests\CAPI2Tools.Tests.ps1'
$Config.CodeCoverage.Enabled = $true
$Config.CodeCoverage.Path = '.\CAPI2Tools.psm1'
$Config.CodeCoverage.OutputPath = '.\Tests\coverage.xml'
Invoke-Pester -Configuration $Config
```

## Test Structure

The test suite is organized into the following contexts:

### Unit Tests

1. **Module Import and Structure**
   - Module loading validation
   - Version checking
   - Exported functions and aliases

2. **Error Code Mappings**
   - Known error code translation
   - Unknown error code handling
   - Error code normalization

3. **Display Character Helper Functions**
   - Unicode character retrieval
   - Cross-version compatibility

4. **Convert-EventLogRecord Function**
   - Event record processing
   - Pipeline support

5. **Export-CapiEvents Function**
   - CSV export
   - JSON export
   - HTML export (with certificate header)
   - XML export
   - Format auto-detection

6. **Get-CapiErrorAnalysis Function**
   - Error detection
   - Summary generation

7. **Compare-CapiEvents Function**
   - Event comparison logic
   - Custom labels

8. **Format-XML Function**
   - XML formatting
   - Custom indentation

9. **Find-CapiEventsByName Function**
   - Parameter validation
   - Pipeline support

10. **Get-CapiTaskIDEvents Function**
    - TaskID-based event retrieval

11. **Event Log Management Functions**
    - Enable/Disable/Clear operations
    - WhatIf support
    - Backup functionality

12. **Workflow Functions**
    - Troubleshooting workflow
    - Session management

13. **Parameter Validation**
    - ValidateSet attributes
    - Mandatory parameters

14. **Error Handling**
    - Graceful error handling
    - Invalid input handling

### Integration Tests

- Complete workflow scenarios
- End-to-end export operations
- Error analysis workflows

## Test Metrics

Expected test results:
- **Total Tests**: ~80+ test cases
- **Coverage**: Core functionality and error paths
- **Duration**: < 30 seconds (unit tests only)

## Continuous Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Pester Tests
  run: |
    Install-Module -Name Pester -Force -SkipPublisherCheck
    Invoke-Pester -Path .\Tests\CAPI2Tools.Tests.ps1 -Output Detailed -CI
```

## Adding New Tests

When adding new functionality to CAPI2Tools:

1. Add corresponding test cases in `CAPI2Tools.Tests.ps1`
2. Follow the existing test structure (Describe/Context/It)
3. Use descriptive test names
4. Include both positive and negative test cases
5. Run all tests before committing changes

## Test Best Practices

- **Isolation**: Each test should be independent
- **Mock Data**: Use mock data for event testing (no live event log dependency)
- **Cleanup**: Use BeforeAll/AfterAll for setup/teardown
- **Readability**: Test names should clearly describe what's being tested
- **Fast**: Unit tests should execute quickly

## Troubleshooting

### Tests Failing?

1. Ensure module is in the correct path
2. Check Pester version (v5+ recommended)
3. Verify no other instances of module are loaded
4. Check file permissions for test exports

### Module Not Loading?

```powershell
# Force reload the module
Remove-Module CAPI2Tools -Force -ErrorAction SilentlyContinue
Import-Module .\CAPI2Tools.psm1 -Force
```

## Contributing

When contributing tests:
- Maintain consistent formatting
- Add comments for complex test logic
- Ensure tests pass before submitting PR
- Update this README if adding new test categories
