<#
.SYNOPSIS
    CAPI2 Event Log Correlation Analysis Toolkit - PowerShell Module
    
.DESCRIPTION
    A comprehensive PowerShell module for analyzing Windows certificate validation chains,
    troubleshooting TLS/SSL connections, and diagnosing CAPI2 cryptographic errors.
    
.NOTES
    Module Name:    CAPI2Tools
    Version:        2.12.0
    Author:         Jan Tiedemann
    Copyright:      (c) 2022-2025 Jan Tiedemann. Licensed under GNU GPL v3.
    
.LINK
    https://github.com/BetaHydri/GetCapiCorrelationTask
#>

#region Error Code Mappings and Helper Functions

# CAPI2 Error Code Reference
$Script:CAPI2ErrorCodes = @{
    '0x80092013' = @{
        Code        = '0x80092013'
        HexCode     = 'CRYPT_E_REVOCATION_OFFLINE'
        Description = 'The revocation function was unable to check revocation because the revocation server was offline.'
        CommonCause = 'Network connectivity issue, CRL/OCSP server unavailable, firewall blocking'
        Resolution  = 'Check network connectivity, verify CRL/OCSP URLs are accessible, check proxy settings'
        Severity    = 'Warning'
    }
    '0x80092012' = @{
        Code        = '0x80092012'
        HexCode     = 'CRYPT_E_REVOKED'
        Description = 'The certificate has been explicitly revoked by its issuer.'
        CommonCause = 'Certificate has been revoked (compromised, replaced, or no longer trusted)'
        Resolution  = 'Obtain a new certificate from the CA, investigate why certificate was revoked'
        Severity    = 'Critical'
    }
    '0x800B0101' = @{
        Code        = '0x800B0101'
        HexCode     = 'CERT_E_EXPIRED'
        Description = 'A required certificate is not within its validity period.'
        CommonCause = 'Certificate has expired, system time is incorrect'
        Resolution  = 'Renew the certificate, verify system time is correct'
        Severity    = 'Critical'
    }
    '0x800B010F' = @{
        Code        = '0x800B010F'
        HexCode     = 'CERT_E_CN_NO_MATCH'
        Description = 'The certificate common name does not match the host name.'
        CommonCause = 'Certificate issued for different hostname, wildcard mismatch'
        Resolution  = 'Obtain certificate with correct CN/SAN, verify hostname is correct'
        Severity    = 'Critical'
    }
    '0x800B0109' = @{
        Code        = '0x800B0109'
        HexCode     = 'CERT_E_UNTRUSTEDROOT'
        Description = 'A certificate chain processed but terminated in a root certificate not trusted.'
        CommonCause = 'Root CA not in trusted store, self-signed certificate'
        Resolution  = 'Install root CA certificate, verify certificate chain'
        Severity    = 'Critical'
    }
    '0x800B010A' = @{
        Code        = '0x800B010A'
        HexCode     = 'CERT_E_CHAINING'
        Description = 'A certificate chain could not be built to a trusted root authority.'
        CommonCause = 'Intermediate certificate missing, broken certificate chain'
        Resolution  = 'Install missing intermediate certificates, verify certificate chain'
        Severity    = 'Critical'
    }
    '0x80096004' = @{
        Code        = '0x80096004'
        HexCode     = 'TRUST_E_CERT_SIGNATURE'
        Description = 'The signature of the certificate cannot be verified.'
        CommonCause = 'Certificate has been tampered with, corrupted certificate'
        Resolution  = 'Re-download/re-install certificate, verify certificate source'
        Severity    = 'Critical'
    }
    '0x800B0111' = @{
        Code        = '0x800B0111'
        HexCode     = 'CERT_E_WRONG_USAGE'
        Description = 'The certificate is not valid for the requested usage.'
        CommonCause = 'Certificate used for wrong purpose (e.g., client auth vs server auth)'
        Resolution  = 'Obtain certificate with correct Extended Key Usage'
        Severity    = 'Error'
    }
    '0x80092010' = @{
        Code        = '0x80092010'
        HexCode     = 'CRYPT_E_NOT_FOUND'
        Description = 'Cannot find object or property.'
        CommonCause = 'Certificate not found in store, missing certificate property'
        Resolution  = 'Verify certificate is installed, check certificate store'
        Severity    = 'Error'
    }
    '0x000001EA' = @{
        Code        = '0x000001EA'
        HexCode     = 'ERROR_NOT_FOUND'
        Description = 'Catalog security information not found for this file hash.'
        CommonCause = 'File not in Windows catalog database (normal for non-system files), catalog lookup failed'
        Resolution  = 'Verify file signature directly if needed, check file source and integrity'
        Severity    = 'Info'
    }
    '0x800B0110' = @{
        Code        = '0x800B0110'
        HexCode     = 'CERT_E_PURPOSE'
        Description = 'The certificate is not valid for the requested purpose.'
        CommonCause = 'Certificate used for incorrect purpose, Extended Key Usage mismatch'
        Resolution  = 'Verify certificate Extended Key Usage (EKU) matches intended purpose'
        Severity    = 'Error'
    }
    '0x800B0112' = @{
        Code        = '0x800B0112'
        HexCode     = 'CERT_E_PATHLENCONST'
        Description = 'A path length constraint in the certificate chain has been violated.'
        CommonCause = 'CA certificate used beyond allowed path depth, intermediate CA chain too long'
        Resolution  = 'Review certificate chain path length constraints, obtain valid certificate chain'
        Severity    = 'Error'
    }
    '0x800B0113' = @{
        Code        = '0x800B0113'
        HexCode     = 'CERT_E_CRITICAL'
        Description = 'A certificate contains an unknown critical extension.'
        CommonCause = 'Certificate has unsupported critical extension, incompatible extension version'
        Resolution  = 'Obtain certificate without unsupported critical extensions, update certificate template'
        Severity    = 'Error'
    }
    '0x800B0114' = @{
        Code        = '0x800B0114'
        HexCode     = 'CERT_E_VALIDITYPERIODNESTING'
        Description = 'The validity periods of the certification chain do not nest correctly.'
        CommonCause = 'Certificate issued before CA certificate validity period, time synchronization issue'
        Resolution  = 'Verify certificate and CA validity periods, check system time, reissue certificate'
        Severity    = 'Error'
    }
    '0x800B0115' = @{
        Code        = '0x800B0115'
        HexCode     = 'CERT_E_INVALID_POLICY'
        Description = 'A required certificate policy is not present or does not meet constraints.'
        CommonCause = 'Certificate policy OID mismatch, policy constraints not satisfied'
        Resolution  = 'Obtain certificate with correct policy OID, review policy requirements'
        Severity    = 'Error'
    }
    '0x80090308' = @{
        Code        = '0x80090308'
        HexCode     = 'SEC_E_INVALID_TOKEN'
        Description = 'The security token provided is invalid or malformed.'
        CommonCause = 'Corrupted authentication token, protocol mismatch, unsupported cipher suite'
        Resolution  = 'Verify TLS/SSL configuration, check cipher suite compatibility, review security settings'
        Severity    = 'Error'
    }
    '0x80090325' = @{
        Code        = '0x80090325'
        HexCode     = 'SEC_E_UNTRUSTED_ROOT'
        Description = 'The certificate chain was issued by an authority that is not trusted.'
        CommonCause = 'Root CA certificate not in Trusted Root store, self-signed certificate'
        Resolution  = 'Install root CA certificate in Trusted Root Certification Authorities store'
        Severity    = 'Critical'
    }
    '0x80090326' = @{
        Code        = '0x80090326'
        HexCode     = 'SEC_E_WRONG_PRINCIPAL'
        Description = 'The target principal name is incorrect (certificate name mismatch).'
        CommonCause = 'Certificate CN/SAN does not match hostname, wildcard certificate mismatch'
        Resolution  = 'Obtain certificate with correct CN/SAN, verify hostname matches certificate'
        Severity    = 'Critical'
    }
    '0x80090327' = @{
        Code        = '0x80090327'
        HexCode     = 'SEC_E_CERT_EXPIRED'
        Description = 'The received certificate has expired or is not yet valid.'
        CommonCause = 'Certificate expired, system time incorrect, certificate not yet valid'
        Resolution  = 'Renew expired certificate, verify system time is correct'
        Severity    = 'Critical'
    }
    '0x8009030C' = @{
        Code        = '0x8009030C'
        HexCode     = 'SEC_E_LOGON_DENIED'
        Description = 'The logon attempt failed due to authentication failure.'
        CommonCause = 'Client certificate authentication failed, mutual TLS error, invalid credentials'
        Resolution  = 'Verify client certificate is valid and trusted, check certificate mapping'
        Severity    = 'Error'
    }
    '0x80092026' = @{
        Code        = '0x80092026'
        HexCode     = 'CRYPT_E_SECURITY_SETTINGS'
        Description = 'Security settings prevent certificate verification or usage.'
        CommonCause = 'Group Policy restrictions, weak signature algorithm blocked, disabled cryptographic provider'
        Resolution  = 'Review security policy settings, check signature algorithm requirements, verify cryptographic settings'
        Severity    = 'Warning'
    }
    '0x80096010' = @{
        Code        = '0x80096010'
        HexCode     = 'TRUST_E_BAD_DIGEST'
        Description = 'The digital signature of the object did not verify correctly.'
        CommonCause = 'File modified after signing, corrupted signature, hash algorithm mismatch'
        Resolution  = 'Re-download or obtain fresh copy of signed object, verify file integrity'
        Severity    = 'Critical'
    }
    'FBF'        = @{
        Code        = 'FBF'
        HexCode     = 'CERT_E_CHAINING'
        Description = 'A certificate chain could not be built to a trusted root authority.'
        CommonCause = 'Intermediate certificate missing, broken certificate chain'
        Resolution  = 'Install missing intermediate certificates, verify certificate chain'
        Severity    = 'Error'
    }
}

# CAPI2 TrustStatus Flag Reference
# ErrorStatus flags indicate trust chain validation errors
$Script:TrustStatusErrorFlags = @{
    '0x00000001' = @{ Flag = 'CERT_TRUST_IS_NOT_TIME_VALID'; Description = 'Certificate is not within its validity period'; Severity = 'Critical' }
    '0x00000002' = @{ Flag = 'CERT_TRUST_IS_NOT_TIME_NESTED'; Description = 'Certificate validity period does not nest correctly'; Severity = 'Error' }
    '0x00000004' = @{ Flag = 'CERT_TRUST_IS_REVOKED'; Description = 'Certificate has been explicitly revoked'; Severity = 'Critical' }
    '0x00000008' = @{ Flag = 'CERT_TRUST_IS_NOT_SIGNATURE_VALID'; Description = 'Certificate signature is not valid'; Severity = 'Critical' }
    '0x00000010' = @{ Flag = 'CERT_TRUST_IS_NOT_VALID_FOR_USAGE'; Description = 'Certificate is not valid for requested usage'; Severity = 'Error' }
    '0x00000020' = @{ Flag = 'CERT_TRUST_IS_UNTRUSTED_ROOT'; Description = 'Certificate chain terminated in untrusted root'; Severity = 'Critical' }
    '0x00000040' = @{ Flag = 'CERT_TRUST_REVOCATION_STATUS_UNKNOWN'; Description = 'Revocation status could not be determined'; Severity = 'Warning' }
    '0x00000080' = @{ Flag = 'CERT_TRUST_IS_CYCLIC'; Description = 'Certificate chain contains a cycle'; Severity = 'Error' }
    '0x00000100' = @{ Flag = 'CERT_TRUST_INVALID_EXTENSION'; Description = 'Certificate has unsupported critical extension'; Severity = 'Error' }
    '0x00000200' = @{ Flag = 'CERT_TRUST_INVALID_POLICY_CONSTRAINTS'; Description = 'Certificate policy constraints are invalid'; Severity = 'Error' }
    '0x00000400' = @{ Flag = 'CERT_TRUST_INVALID_BASIC_CONSTRAINTS'; Description = 'Certificate basic constraints are invalid'; Severity = 'Error' }
    '0x00000800' = @{ Flag = 'CERT_TRUST_INVALID_NAME_CONSTRAINTS'; Description = 'Certificate name constraints are invalid'; Severity = 'Error' }
    '0x00001000' = @{ Flag = 'CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT'; Description = 'Certificate has unsupported name constraint'; Severity = 'Warning' }
    '0x00002000' = @{ Flag = 'CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT'; Description = 'Certificate has undefined name constraint'; Severity = 'Warning' }
    '0x00004000' = @{ Flag = 'CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT'; Description = 'Certificate has not permitted name constraint'; Severity = 'Error' }
    '0x00008000' = @{ Flag = 'CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT'; Description = 'Certificate has excluded name constraint'; Severity = 'Error' }
    '0x01000000' = @{ Flag = 'CERT_TRUST_IS_OFFLINE_REVOCATION'; Description = 'Revocation server was offline'; Severity = 'Warning' }
    '0x02000000' = @{ Flag = 'CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY'; Description = 'No issuance chain policy found'; Severity = 'Warning' }
    '0x04000000' = @{ Flag = 'CERT_TRUST_IS_EXPLICIT_DISTRUST'; Description = 'Certificate is explicitly distrusted'; Severity = 'Critical' }
    '0x08000000' = @{ Flag = 'CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT'; Description = 'Certificate has unsupported critical extension'; Severity = 'Error' }
    '0x10000000' = @{ Flag = 'CERT_TRUST_HAS_WEAK_SIGNATURE'; Description = 'Certificate has weak cryptographic signature'; Severity = 'Warning' }
}

# InfoStatus flags provide additional trust chain information
$Script:TrustStatusInfoFlags = @{
    '0x00000001' = @{ Flag = 'CERT_TRUST_HAS_EXACT_MATCH_ISSUER'; Description = 'Exact match issuer certificate found' }
    '0x00000002' = @{ Flag = 'CERT_TRUST_HAS_KEY_MATCH_ISSUER'; Description = 'Key match issuer certificate found' }
    '0x00000004' = @{ Flag = 'CERT_TRUST_HAS_NAME_MATCH_ISSUER'; Description = 'Name match issuer certificate found' }
    '0x00000008' = @{ Flag = 'CERT_TRUST_IS_SELF_SIGNED'; Description = 'Certificate is self-signed' }
    '0x00000010' = @{ Flag = 'CERT_TRUST_AUTO_UPDATE_CA_REVOCATION'; Description = 'Auto update CA revocation enabled' }
    '0x00000020' = @{ Flag = 'CERT_TRUST_AUTO_UPDATE_END_REVOCATION'; Description = 'Auto update end entity revocation enabled' }
    '0x00000040' = @{ Flag = 'CERT_TRUST_NO_OCSP_FAILOVER_TO_CRL'; Description = 'No OCSP failover to CRL' }
    '0x00000100' = @{ Flag = 'CERT_TRUST_HAS_PREFERRED_ISSUER'; Description = 'Preferred issuer certificate found' }
    '0x00000200' = @{ Flag = 'CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY'; Description = 'Issuance chain policy present' }
    '0x00000400' = @{ Flag = 'CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS'; Description = 'Valid name constraints present' }
    '0x00010000' = @{ Flag = 'CERT_TRUST_IS_PEER_TRUSTED'; Description = 'Certificate is peer trusted' }
    '0x00020000' = @{ Flag = 'CERT_TRUST_HAS_CRL_VALIDITY_EXTENDED'; Description = 'CRL validity period extended' }
    '0x01000000' = @{ Flag = 'CERT_TRUST_IS_COMPLEX_CHAIN'; Description = 'Certificate chain is complex' }
}

function Get-CAPI2ErrorDetails {
    <#
    .SYNOPSIS
        Translates CAPI2 error codes to human-readable descriptions with resolution steps.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ErrorCode
    )
    
    # Normalize error code format
    # Remove any whitespace
    $ErrorCode = $ErrorCode.Trim()
    
    # If it's a hex string without 0x prefix, add it
    if ($ErrorCode -match '^[0-9A-Fa-f]{8}$') {
        $ErrorCode = "0x$ErrorCode"
    }
    # If it's a decimal number, convert to hex
    elseif ($ErrorCode -match '^[0-9]+$') {
        $ErrorCode = "0x{0:X8}" -f [int64]$ErrorCode
    }
    # Ensure 0x prefix is lowercase for consistency
    $ErrorCode = $ErrorCode -replace '^0X', '0x'
    
    if ($Script:CAPI2ErrorCodes.ContainsKey($ErrorCode)) {
        return $Script:CAPI2ErrorCodes[$ErrorCode]
    }
    else {
        return @{
            Code        = $ErrorCode
            HexCode     = 'UNKNOWN'
            Description = 'Unknown error code'
            CommonCause = 'Unknown'
            Resolution  = 'Search Microsoft documentation for error code'
            Severity    = 'Unknown'
        }
    }
}

function Get-TrustStatusDetails {
    <#
    .SYNOPSIS
        Parses TrustStatus XML elements and returns detailed flag information.
        
    .DESCRIPTION
        Extracts ErrorStatus and InfoStatus values from TrustStatus elements in CAPI2 events,
        parses the bit flags, and returns human-readable descriptions.
        
    .PARAMETER TrustStatusNode
        XML node containing TrustStatus element with ErrorStatus and InfoStatus children
        
    .EXAMPLE
        $TrustNode = $EventXml.SelectSingleNode("//TrustStatus")
        Get-TrustStatusDetails -TrustStatusNode $TrustNode
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$TrustStatusNode
    )
    
    $Result = [PSCustomObject]@{
        ErrorFlags = @()
        InfoFlags  = @()
        HasErrors  = $false
        Severity   = 'Info'
    }
    
    # Parse ErrorStatus
    $ErrorStatusNode = $TrustStatusNode.SelectSingleNode("*[local-name()='ErrorStatus' and @value]")
    if ($ErrorStatusNode) {
        $ErrorValue = $ErrorStatusNode.GetAttribute('value')
        
        if ($ErrorValue -ne "0") {
            $Result.HasErrors = $true
            
            # Convert to integer for bit manipulation
            $ErrorInt = if ($ErrorValue -match '^0x') {
                [Convert]::ToInt64($ErrorValue, 16)
            }
            else {
                [int64]$ErrorValue
            }
            
            # Check each error flag bit
            foreach ($FlagEntry in $Script:TrustStatusErrorFlags.GetEnumerator()) {
                $FlagValue = [Convert]::ToInt64($FlagEntry.Key, 16)
                
                if (($ErrorInt -band $FlagValue) -eq $FlagValue) {
                    $FlagInfo = $FlagEntry.Value
                    $Result.ErrorFlags += [PSCustomObject]@{
                        Flag        = $FlagInfo.Flag
                        Description = $FlagInfo.Description
                        Severity    = $FlagInfo.Severity
                    }
                    
                    # Track highest severity
                    if ($FlagInfo.Severity -eq 'Critical') {
                        $Result.Severity = 'Critical'
                    }
                    elseif ($FlagInfo.Severity -eq 'Error' -and $Result.Severity -ne 'Critical') {
                        $Result.Severity = 'Error'
                    }
                    elseif ($FlagInfo.Severity -eq 'Warning' -and $Result.Severity -notin @('Critical', 'Error')) {
                        $Result.Severity = 'Warning'
                    }
                }
            }
        }
    }
    
    # Parse InfoStatus
    $InfoStatusNode = $TrustStatusNode.SelectSingleNode("*[local-name()='InfoStatus' and @value]")
    if ($InfoStatusNode) {
        $InfoValue = $InfoStatusNode.GetAttribute('value')
        
        # Convert to integer for bit manipulation
        $InfoInt = if ($InfoValue -match '^0x') {
            [Convert]::ToInt64($InfoValue, 16)
        }
        else {
            [int64]$InfoValue
        }
        
        # Check each info flag bit
        foreach ($FlagEntry in $Script:TrustStatusInfoFlags.GetEnumerator()) {
            $FlagValue = [Convert]::ToInt64($FlagEntry.Key, 16)
            
            if (($InfoInt -band $FlagValue) -eq $FlagValue) {
                $FlagInfo = $FlagEntry.Value
                $Result.InfoFlags += [PSCustomObject]@{
                    Flag        = $FlagInfo.Flag
                    Description = $FlagInfo.Description
                }
            }
        }
    }
    
    return $Result
}

#endregion

#region Helper Functions for Display Characters

function Get-DisplayChar {
    <#
    .SYNOPSIS
        Returns display characters compatible with PowerShell 5.1 and 7.
        
    .DESCRIPTION
        Centralized function to get Unicode characters using hex encoding for cross-version compatibility.
        
    .PARAMETER Name
        The name of the character to retrieve.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('BoxTopLeft', 'BoxTopRight', 'BoxBottomLeft', 'BoxBottomRight', 
            'BoxVertical', 'BoxHorizontal', 'Checkmark', 'CheckmarkBold',
            'Wrench', 'Flag', 'Lightbulb', 'Warning', 'Lock', 'Clipboard',
            'RightArrow', 'Bullet')]
        [string]$Name
    )
    
    switch ($Name) {
        'BoxTopLeft' { return [char]0x2554 }  # ╔
        'BoxTopRight' { return [char]0x2557 }  # ╗
        'BoxBottomLeft' { return [char]0x255A }  # ╚
        'BoxBottomRight' { return [char]0x255D }  # ╝
        'BoxVertical' { return [char]0x2551 }  # ║
        'BoxHorizontal' { return [char]0x2550 }  # ═
        'Checkmark' { return [char]0x2713 }  # ✓
        'CheckmarkBold' { return [char]0x2713 }  # ✓ (simplified for compatibility)
        'Wrench' { return [char]0x2692 } # ⚒ (hammer and pick, compatible alternative)
        'Flag' { return [char]0x2691 } # ⚑ (flag, compatible alternative)
        'Lightbulb' { return [char]0x2600 } # ☀ (sun/bright idea, compatible alternative)
        'Warning' { return [char]0x26A0 }  # ⚠
        'Lock' { return [char]0x2612 } # ☒ (ballot box, compatible alternative)
        'Clipboard' { return [char]0x2630 } # ☰ (trigram, compatible alternative)
        'RightArrow' { return [char]0x2192 }  # →
        'Bullet' { return '*' }           # *
    }
}

function Write-BoxHeader {
    <#
    .SYNOPSIS
        Writes a formatted box header to the console.
        
    .DESCRIPTION
        Creates a consistent box-drawing header for workflow steps.
        
    .PARAMETER Text
        The text to display in the header.
        
    .PARAMETER Icon
        Optional icon name to display before the text.
        
    .PARAMETER Color
        Console color for the header (default: Cyan).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,
        
        [Parameter(Mandatory = $false)]
        [string]$Icon,
        
        [Parameter(Mandatory = $false)]
        [string]$Color = 'Cyan'
    )
    
    $Width = 63
    $Line = (Get-DisplayChar 'BoxHorizontal').ToString() * $Width
    
    $DisplayText = if ($Icon) {
        "$(Get-DisplayChar $Icon) $Text"
    }
    else {
        $Text
    }
    
    # Calculate padding
    $TextLength = $Text.Length + $(if ($Icon) { 2 } else { 0 })
    $PaddingLeft = [Math]::Floor(($Width - $TextLength) / 2)
    $PaddingRight = $Width - $TextLength - $PaddingLeft
    
    $TopLine = "$(Get-DisplayChar 'BoxTopLeft')$Line$(Get-DisplayChar 'BoxTopRight')"
    $MiddleLine = "$(Get-DisplayChar 'BoxVertical')$(' ' * $PaddingLeft)$DisplayText$(' ' * $PaddingRight)$(Get-DisplayChar 'BoxVertical')"
    $BottomLine = "$(Get-DisplayChar 'BoxBottomLeft')$Line$(Get-DisplayChar 'BoxBottomRight')"
    
    Write-Host "`n$TopLine" -ForegroundColor $Color
    Write-Host $MiddleLine -ForegroundColor $Color
    Write-Host "$BottomLine`n" -ForegroundColor $Color
}

#endregion

#region CAPI2 Event Log Management Functions

function Enable-CAPI2EventLog {
    <#
    .SYNOPSIS
        Enables the CAPI2 Operational event log for certificate troubleshooting.
        
    .DESCRIPTION
        Enables detailed certificate validation logging in the Microsoft-Windows-CAPI2/Operational log.
        Requires administrative privileges.
        
    .EXAMPLE
        Enable-CAPI2EventLog
        
    .EXAMPLE
        Enable-CAPI2EventLog -Verbose
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    try {
        $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $IsAdmin) {
            Write-Warning "This function requires administrative privileges. Please run PowerShell as Administrator."
            return
        }
        
        Write-Verbose "Checking current CAPI2 log status..."
        $LogDetails = wevtutil.exe gl Microsoft-Windows-CAPI2/Operational
        
        if ($LogDetails -match "enabled:\s+true") {
            Write-Host "CAPI2 Event Log is already enabled." -ForegroundColor Green
            return
        }
        
        if ($PSCmdlet.ShouldProcess("Microsoft-Windows-CAPI2/Operational", "Enable event log")) {
            Write-Host "Enabling CAPI2 Operational Event Log..." -ForegroundColor Cyan
            wevtutil.exe sl Microsoft-Windows-CAPI2/Operational /e:true
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "$(Get-DisplayChar 'Checkmark') CAPI2 Event Log successfully enabled." -ForegroundColor Green
                Write-Host "  Certificate validation events will now be logged." -ForegroundColor Gray
            }
            else {
                Write-Error "Failed to enable CAPI2 Event Log. Exit code: $LASTEXITCODE"
            }
        }
    }
    catch {
        Write-Error "Error enabling CAPI2 Event Log: $($_.Exception.Message)"
    }
}

function Disable-CAPI2EventLog {
    <#
    .SYNOPSIS
        Disables the CAPI2 Operational event log.
        
    .DESCRIPTION
        Disables certificate validation logging in the Microsoft-Windows-CAPI2/Operational log.
        Requires administrative privileges. Use this to reduce log volume when troubleshooting is complete.
        
    .EXAMPLE
        Disable-CAPI2EventLog
        
    .EXAMPLE
        Disable-CAPI2EventLog -Verbose
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    try {
        $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $IsAdmin) {
            Write-Warning "This function requires administrative privileges. Please run PowerShell as Administrator."
            return
        }
        
        Write-Verbose "Checking current CAPI2 log status..."
        $LogDetails = wevtutil.exe gl Microsoft-Windows-CAPI2/Operational
        
        if ($LogDetails -match "enabled:\s+false") {
            Write-Host "CAPI2 Event Log is already disabled." -ForegroundColor Yellow
            return
        }
        
        if ($PSCmdlet.ShouldProcess("Microsoft-Windows-CAPI2/Operational", "Disable event log")) {
            Write-Host "Disabling CAPI2 Operational Event Log..." -ForegroundColor Cyan
            wevtutil.exe sl Microsoft-Windows-CAPI2/Operational /e:false
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "$(Get-DisplayChar 'Checkmark') CAPI2 Event Log successfully disabled." -ForegroundColor Green
                Write-Host "  Certificate validation events will no longer be logged." -ForegroundColor Gray
            }
            else {
                Write-Error "Failed to disable CAPI2 Event Log. Exit code: $LASTEXITCODE"
            }
        }
    }
    catch {
        Write-Error "Error disabling CAPI2 Event Log: $($_.Exception.Message)"
    }
}

function Clear-CAPI2EventLog {
    <#
    .SYNOPSIS
        Clears all events from the CAPI2 Operational event log.
        
    .DESCRIPTION
        Removes all existing events from the Microsoft-Windows-CAPI2/Operational log.
        Requires administrative privileges. Useful for starting fresh troubleshooting sessions.
        
    .PARAMETER Backup
        If specified, backs up the log before clearing to the specified path.
        
    .EXAMPLE
        Clear-CAPI2EventLog
        
    .EXAMPLE
        Clear-CAPI2EventLog -Backup "C:\Logs\CAPI2_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
        
    .EXAMPLE
        Clear-CAPI2EventLog -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Backup
    )
    
    try {
        $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $IsAdmin) {
            Write-Warning "This function requires administrative privileges. Please run PowerShell as Administrator."
            return
        }
        
        # Count current events
        $EventCount = (Get-WinEvent -LogName Microsoft-Windows-CAPI2/Operational -ErrorAction SilentlyContinue | Measure-Object).Count
        
        if ($EventCount -eq 0) {
            Write-Host "CAPI2 Event Log is already empty." -ForegroundColor Yellow
            return
        }
        
        Write-Host "Current CAPI2 Event Log contains $EventCount events." -ForegroundColor Cyan
        
        # Backup if requested
        if ($Backup) {
            if ($PSCmdlet.ShouldProcess($Backup, "Backup CAPI2 Event Log")) {
                Write-Host "Backing up CAPI2 Event Log to: $Backup" -ForegroundColor Cyan
                wevtutil.exe epl Microsoft-Windows-CAPI2/Operational "$Backup"
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "$(Get-DisplayChar 'Checkmark') Backup completed successfully." -ForegroundColor Green
                }
                else {
                    Write-Error "Failed to backup CAPI2 Event Log. Exit code: $LASTEXITCODE"
                    return
                }
            }
        }
        
        # Clear the log
        if ($PSCmdlet.ShouldProcess("Microsoft-Windows-CAPI2/Operational", "Clear event log ($EventCount events)")) {
            Write-Host "Clearing CAPI2 Operational Event Log..." -ForegroundColor Cyan
            wevtutil.exe cl Microsoft-Windows-CAPI2/Operational
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "$(Get-DisplayChar 'Checkmark') CAPI2 Event Log successfully cleared." -ForegroundColor Green
                Write-Host "  $EventCount events removed. Log is now empty." -ForegroundColor Gray
            }
            else {
                Write-Error "Failed to clear CAPI2 Event Log. Exit code: $LASTEXITCODE"
            }
        }
    }
    catch {
        Write-Error "Error clearing CAPI2 Event Log: $($_.Exception.Message)"
    }
}

function Get-CAPI2EventLogStatus {
    <#
    .SYNOPSIS
        Displays the current status of the CAPI2 Operational event log.
        
    .DESCRIPTION
        Shows whether CAPI2 logging is enabled, the number of events, and log file details.
        
    .EXAMPLE
        Get-CAPI2EventLogStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "`n=== CAPI2 Event Log Status ===" -ForegroundColor Cyan
        
        $LogDetails = wevtutil.exe gl Microsoft-Windows-CAPI2/Operational 2>&1 | Out-String
        
        # Parse log details
        $Enabled = if ($LogDetails -match "enabled:\s+(\w+)") { $matches[1] } else { "Unknown" }
        $LogMode = if ($LogDetails -match "logFileName:\s+(.+)") { $matches[1].Trim() } else { "Unknown" }
        $MaxSize = if ($LogDetails -match "maxSize:\s+(\d+)") { [math]::Round([int64]$matches[1] / 1MB, 2) } else { "Unknown" }
        
        # Count events
        $EventCount = (Get-WinEvent -LogName Microsoft-Windows-CAPI2/Operational -ErrorAction SilentlyContinue | Measure-Object).Count
        
        # Get oldest and newest events
        $OldestEvent = Get-WinEvent -LogName Microsoft-Windows-CAPI2/Operational -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
        $NewestEvent = Get-WinEvent -LogName Microsoft-Windows-CAPI2/Operational -MaxEvents 1 -ErrorAction SilentlyContinue
        
        Write-Host "Status:          " -NoNewline
        if ($Enabled -eq "true") {
            Write-Host "ENABLED" -ForegroundColor Green
        }
        else {
            Write-Host "DISABLED" -ForegroundColor Red
        }
        
        Write-Host "Event Count:     $EventCount" -ForegroundColor White
        Write-Host "Max Size:        $MaxSize MB" -ForegroundColor White
        
        if ($OldestEvent) {
            Write-Host "Oldest Event:    $($OldestEvent.TimeCreated)" -ForegroundColor Gray
        }
        if ($NewestEvent) {
            Write-Host "Newest Event:    $($NewestEvent.TimeCreated)" -ForegroundColor Gray
        }
        
        Write-Host "Log Location:    $LogMode" -ForegroundColor Gray
        Write-Host ""
        
        if ($Enabled -eq "false") {
            Write-Host "$(Get-DisplayChar 'Lightbulb') Tip: Run 'Enable-CAPI2EventLog' to enable certificate event logging." -ForegroundColor Yellow
        }
        
        if ($EventCount -eq 0) {
            Write-Host "$(Get-DisplayChar 'Lightbulb') Tip: No events found. Perform certificate operations to generate events." -ForegroundColor Yellow
        }
        
    }
    catch {
        Write-Error "Error retrieving CAPI2 Event Log status: $($_.Exception.Message)"
    }
}

#endregion

function Find-CapiEventsByName {
    <#
      .SYNOPSIS
          Searches CAPI2 events by DNS name, certificate subject, or process name and retrieves all correlated events.
            
      .DESCRIPTION
          This function allows administrators to find certificate validation chains by searching for a DNS name, 
          certificate subject, or process name without needing to know the TaskID beforehand. It searches the CAPI2 log,
          identifies all TaskIDs associated with the specified name, and retrieves all correlated events.
          
          Searches in the following fields:
          - subjectName attribute (certificate subject)
          - CN (Common Name) elements
          - SubjectAltName/DNSName elements (SAN)
          - ProcessName attribute (from EventAuxInfo - useful for finding events by application)
          - Full XML content (fallback)
            
      .PARAMETER Name
          The name to search for - can be:
          - DNS name (e.g., "bing.com", "*.microsoft.com")
          - Certificate subject or CN (e.g., "DigiCert", "VeriSign")
          - Process name (e.g., "chrome.exe", "outlook.exe")
          Supports wildcard matching.
       
      .PARAMETER MaxEvents
          Maximum number of events to retrieve for initial search (default: 1000)
          
      .PARAMETER Hours
          Number of hours to look back in the event log (default: 24)
          
      .PARAMETER IncludePattern
          If specified, only returns events matching this pattern in the certificate details.
          For common scenarios, use -FilterType instead for autocomplete suggestions.
          
      .PARAMETER FilterType
          Pre-defined filters for common troubleshooting scenarios:
          - Revocation: Events related to revocation checking (OCSP, CRL)
          - Expired: Certificate expiration issues
          - Untrusted: Trust chain and root certificate issues
          - ChainBuilding: Certificate chain construction events
          - PolicyValidation: Certificate policy validation events
          - SignatureValidation: Certificate signature verification
          - ErrorsOnly: Events containing Result errors
          
      .EXAMPLE
          Find-CapiEventsByName -Name "bing.com"
          Finds all CAPI2 correlation chains for bing.com
      
      .EXAMPLE
          Find-CapiEventsByName -Name "*.microsoft.com" -Hours 48
          Finds all Microsoft-related certificate chains in the last 48 hours
          
      .EXAMPLE
          Find-CapiEventsByName -Name "DigiCert" -FilterType Revocation
          Finds DigiCert certificates with revocation-related events (uses predefined filter)
          
      .EXAMPLE
          Find-CapiEventsByName -Name "*.contoso.com" -FilterType Expired
          Finds contoso.com certificates with expiration issues
          
      .EXAMPLE
          Find-CapiEventsByName -Name "site.com" -IncludePattern "OCSP"
          Finds site.com events containing "OCSP" (custom pattern)
          
      .EXAMPLE
          Find-CapiEventsByName -Name "chrome.exe"
          Finds all certificate validations performed by Chrome browser
          
      .EXAMPLE
          Find-CapiEventsByName -Name "outlook.exe" -Hours 4
          Finds certificate events from Outlook in the last 4 hours
      
      .OUTPUTS
          Returns grouped objects with TaskID and all correlated events
  #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]
        $Name,
        
        [Parameter(Mandatory = $false)]
        [int]
        $MaxEvents = 1000,
        
        [Parameter(Mandatory = $false)]
        [int]
        $Hours = 24,
        
        [Parameter(Mandatory = $false)]
        [string]
        $IncludePattern,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Revocation', 'Expired', 'Untrusted', 'ChainBuilding', 'PolicyValidation', 'SignatureValidation', 'ErrorsOnly')]
        [string]
        $FilterType
    )
    
    begin {
        Write-Verbose "[BEGIN  ] Starting: $($MyInvocation.Mycommand)"
        $StartTime = (Get-Date).AddHours(-$Hours)
        
        # Map FilterType to actual search patterns
        if ($FilterType) {
            $IncludePattern = switch ($FilterType) {
                'Revocation' { '*revocation*' }
                'Expired' { '*expired*' }
                'Untrusted' { '*untrusted*' }
                'ChainBuilding' { '*CertGetCertificateChain*' }
                'PolicyValidation' { '*CertVerifyCertificateChainPolicy*' }
                'SignatureValidation' { '*signature*' }
                'ErrorsOnly' { '*<Result value=*' }
            }
            Write-Verbose "FilterType '$FilterType' mapped to pattern: $IncludePattern"
        }
    }
    
    process {
        try {
            Write-Host "Searching for certificate events containing '$Name' in the last $Hours hours..." -ForegroundColor Cyan
            
            # Retrieve recent CAPI2 events
            $FilterHash = @{
                LogName   = 'Microsoft-Windows-CAPI2/Operational'
                StartTime = $StartTime
            }
            
            Write-Verbose "Retrieving events from CAPI2 log..."
            $AllEvents = Get-WinEvent -FilterHashtable $FilterHash -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
            
            if ($null -eq $AllEvents) {
                Write-Warning "No CAPI2 events found in the specified time range."
                return
            }
            
            Write-Host "Retrieved $($AllEvents.Count) events. Searching for matching certificates..." -ForegroundColor Yellow
            
            # Convert events and search for the name pattern
            $ConvertedEvents = $AllEvents | Convert-EventLogRecord
            
            # Create wildcard pattern for matching
            $WildcardPattern = "*$Name*"
            
            # Find matching events and extract TaskIDs
            # Search in: subjectName, SubjectAltName/DNSName, CN, ProcessName
            $MatchingTaskIDs = $ConvertedEvents | Where-Object {
                $EventXml = $_.UserData
                if ($null -ne $EventXml) {
                    $XmlString = $EventXml.ToString()
                    $IsMatch = $false
                    
                    # Try to parse as XML for detailed field search
                    try {
                        [xml]$ParsedXml = $EventXml
                        
                        # Search in subjectName attribute
                        $SubjectNameNodes = $ParsedXml.SelectNodes("//*[@subjectName]")
                        foreach ($node in $SubjectNameNodes) {
                            if ($node.subjectName -like $WildcardPattern) {
                                $IsMatch = $true
                                break
                            }
                        }
                        
                        # Search in CN (Common Name) elements
                        if (-not $IsMatch) {
                            $CNNodes = $ParsedXml.SelectNodes("//CN")
                            foreach ($node in $CNNodes) {
                                if ($node.InnerText -like $WildcardPattern) {
                                    $IsMatch = $true
                                    break
                                }
                            }
                        }
                        
                        # Search in SubjectAltName/DNSName elements
                        if (-not $IsMatch) {
                            $DNSNameNodes = $ParsedXml.SelectNodes("//SubjectAltName/DNSName")
                            foreach ($node in $DNSNameNodes) {
                                if ($node.InnerText -like $WildcardPattern) {
                                    $IsMatch = $true
                                    break
                                }
                            }
                        }
                        
                        # Search in ProcessName attribute (EventAuxInfo)
                        if (-not $IsMatch) {
                            $ProcessNameNodes = $ParsedXml.SelectNodes("//*[@ProcessName]")
                            foreach ($node in $ProcessNameNodes) {
                                if ($node.ProcessName -like $WildcardPattern) {
                                    $IsMatch = $true
                                    break
                                }
                            }
                        }
                        
                        # Fallback: search in entire XML string
                        if (-not $IsMatch -and $XmlString -like $WildcardPattern) {
                            $IsMatch = $true
                        }
                    }
                    catch {
                        # If XML parsing fails, fallback to string search
                        if ($XmlString -like $WildcardPattern) {
                            $IsMatch = $true
                        }
                    }
                    
                    # Apply additional include pattern if specified
                    if ($IsMatch -and $IncludePattern) {
                        $IsMatch = $XmlString -like "*$IncludePattern*"
                    }
                    
                    $IsMatch
                }
            } | ForEach-Object {
                # Extract chainRef as TaskID from the event (modern CAPI2 correlation)
                try {
                    [xml]$EventXml = $_.UserData
                    # Look for chainRef attribute in CertificateChain or Certificate elements
                    $ChainRefNode = $EventXml.SelectSingleNode("//*[@chainRef]")
                    if ($null -ne $ChainRefNode) {
                        $TaskId = $ChainRefNode.chainRef
                        if ($TaskId) {
                            # Remove curly braces if present
                            $TaskId = $TaskId.Trim('{}')
                            [PSCustomObject]@{
                                TaskID      = $TaskId
                                TimeCreated = $_.TimeCreated
                                Preview     = $_.Message.Substring(0, [Math]::Min(150, $_.Message.Length))
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not extract chainRef from event: $_"
                }
            } | Select-Object -Property TaskID, TimeCreated, Preview -Unique | Sort-Object -Property TimeCreated -Descending
            
            if ($null -eq $MatchingTaskIDs -or $MatchingTaskIDs.Count -eq 0) {
                Write-Warning "No events found matching '$Name'."
                Write-Host "Try:" -ForegroundColor Yellow
                Write-Host "  - Increasing the -Hours parameter" -ForegroundColor Yellow
                Write-Host "  - Using a broader search term" -ForegroundColor Yellow
                Write-Host "  - Checking if CAPI2 logging is enabled" -ForegroundColor Yellow
                return
            }
            
            Write-Host "`nFound $($MatchingTaskIDs.Count) correlation chain(s) matching '$Name':" -ForegroundColor Green
            $MatchingTaskIDs | ForEach-Object {
                Write-Host "  TaskID: $($_.TaskID) - $($_.TimeCreated) - $($_.Preview)..." -ForegroundColor Gray
            }
            
            # Retrieve all events for each TaskID
            Write-Host "`nRetrieving full correlation chains..." -ForegroundColor Cyan
            
            $AllResults = @()
            foreach ($Match in $MatchingTaskIDs) {
                Write-Verbose "Processing TaskID: $($Match.TaskID)"
                $CorrelatedEvents = Get-CapiTaskIDEvents -TaskID $Match.TaskID
                
                if ($CorrelatedEvents) {
                    $AllResults += [PSCustomObject]@{
                        TaskID      = $Match.TaskID
                        TimeCreated = $Match.TimeCreated
                        EventCount  = $CorrelatedEvents.Count
                        Events      = $CorrelatedEvents
                        SearchTerm  = $Name
                    }
                }
            }
            
            Write-Host "`nSuccessfully retrieved $($AllResults.Count) correlation chain(s)." -ForegroundColor Green
            
            return $AllResults
            
        }
        catch {
            Write-Warning "Error during search: $($_.Exception.Message)"
        }
    }
    
    end {
        Write-Verbose "[END    ] Ending: $($MyInvocation.Mycommand)"
    }
}

function Get-CapiTaskIDEvents {
    <#
      .SYNOPSIS
          Retrieves all CAPI2 events that share the same correlation TaskID.
            
      .DESCRIPTION
          In the CAPI2 log, events belonging to the same certificate validation chain share a TaskID. 
          This function retrieves all events in the sequence based on the provided TaskID.
            
      .PARAMETER TaskID
          The correlation TaskID (GUID) that identifies a specific certificate validation sequence.
          Can be obtained from a single event or using Find-CapiEventsByName.
       
      .EXAMPLE
          Get-CapiTaskIDEvents -TaskID "7E11B6A3-50EA-47ED-928D-BBE4784EFA3F" | Format-List
          
      .EXAMPLE
          $Results = Find-CapiEventsByName -Name "microsoft.com"
          $Results[0].Events | Format-Table
      
      .OUTPUTS
          TimeCreated     : 10/25/2022 3:48:50 PM
          ID              : 10
          RecordType      : Informationen
          DetailedMessage : <CertGetCertificateChainStart xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventAuxInfo
                            ProcessName="msedge.exe" /><CorrelationAuxInfo TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="1"
                            /></CertGetCertificateChainStart>
  
          TimeCreated     : 10/25/2022 3:48:50 PM
          ID              : 40
          RecordType      : Informationen
          DetailedMessage : <CertVerifyRevocationStart xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventAuxInfo
                            ProcessName="msedge.exe" /><CorrelationAuxInfo TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="2"
                            /></CertVerifyRevocationStart>
  
          [... additional events ...]
  #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]
        $TaskID
    )
    try {
        # CAPI2 uses TWO correlation mechanisms:
        # 1. chainRef - Links certificate chain events (IDs 11, 30, 81)
        # 2. CorrelationAuxInfo TaskId - Links full workflow events (IDs 10, 11, 30, 40, 41, 50, 51, 80, 81, 90)
        
        # Normalize TaskID format - remove braces if present, we'll add them in queries
        $TaskID = $TaskID.Trim('{}')
        
        # First, try to find events by chainRef (most common scenario)
        $QueryChainRef = "*[UserData/CertVerifyCertificateChainPolicy/CertificateChain[@chainRef='{$TaskID}']] or 
        *[UserData/CertGetCertificateChain/CertificateChain[@chainRef='{$TaskID}']] or
        *[UserData/WinVerifyTrust/CertificateChain[@chainRef='{$TaskID}']] or
        *[UserData/X509Objects/Certificate[@chainRef='{$TaskID}']]"
        
        $ChainRefEvents = Get-WinEvent -FilterXPath $QueryChainRef -LogName Microsoft-Windows-CAPI2/Operational -ErrorAction SilentlyContinue
        
        # If found, get the CorrelationAuxInfo TaskId from one of these events to find ALL related events
        if ($ChainRefEvents) {
            $CorrelationTaskId = $null
            foreach ($evt in $ChainRefEvents) {
                try {
                    [xml]$EventXml = $evt.ToXml()
                    $TaskIdNode = $EventXml.SelectSingleNode("//CorrelationAuxInfo[@TaskId]")
                    if ($null -ne $TaskIdNode) {
                        $CorrelationTaskId = $TaskIdNode.TaskId.Trim('{}')
                        break
                    }
                }
                catch { }
            }
            
            # If we found a CorrelationAuxInfo TaskId, query for all events in the workflow
            if ($CorrelationTaskId) {
                Write-Verbose "Found CorrelationAuxInfo TaskId: $CorrelationTaskId"
                $QueryTaskId = "*[UserData/*/CorrelationAuxInfo[@TaskId='{$CorrelationTaskId}']]"
                $AllEvents = Get-WinEvent -FilterXPath $QueryTaskId -LogName Microsoft-Windows-CAPI2/Operational -ErrorAction SilentlyContinue
                
                if ($AllEvents) {
                    $Events = $AllEvents | Convert-EventLogRecord | Select-Object -Property TimeCreated, Id, Level, LevelDisplayName, RecordType, @{N = 'DetailedMessage'; E = { (Format-XML $_.UserData) } } | Sort-Object -Property TimeCreated
                    return $Events
                }
            }
            
            # Fallback: return just the chainRef events if we couldn't find CorrelationAuxInfo
            $Events = $ChainRefEvents | Convert-EventLogRecord | Select-Object -Property TimeCreated, Id, Level, LevelDisplayName, RecordType, @{N = 'DetailedMessage'; E = { (Format-XML $_.UserData) } } | Sort-Object -Property TimeCreated
            return $Events
        }
        
        # If chainRef didn't work, try searching directly by CorrelationAuxInfo TaskId (legacy format or direct TaskId search)
        $QueryTaskId = "*[UserData/*/CorrelationAuxInfo[@TaskId='{$TaskID}']]"
        $RawEvents = Get-WinEvent -FilterXPath $QueryTaskId -LogName Microsoft-Windows-CAPI2/Operational -ErrorAction SilentlyContinue
        
        if ($RawEvents) {
            Write-Verbose "Found $($RawEvents.Count) raw events, converting..."
            $Events = $RawEvents | Convert-EventLogRecord | Select-Object -Property TimeCreated, Id, Level, LevelDisplayName, RecordType, @{N = 'DetailedMessage'; E = { (Format-XML $_.UserData) } } | Sort-Object -Property TimeCreated
            
            if ($Events -and $Events.Count -gt 0) {
                Write-Verbose "Returning $($Events.Count) converted events"
                return $Events
            }
        }
        
        Write-Host "No Capi2 Event were found with the CorrelationID $TaskID" -ForegroundColor Yellow
        return $null
    }
    catch {
        Write-Warning -Message $_.Exception.Message
    }
}
  
function Convert-EventLogRecord {
  
    [cmdletbinding()]
    [alias("clr")]
  
    param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [ValidateNotNullorEmpty()]
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$LogRecord
    )
  
    begin {
        Write-Verbose "[BEGIN  ] Starting: $($MyInvocation.Mycommand)"
    } #begin
  
    process {
        foreach ($record in $LogRecord) {
            Write-Verbose "[PROCESS] Processing event id $($record.ID) from $($record.logname) log on $($record.machinename)"
            Write-Verbose "[PROCESS] Creating XML data"
            [xml]$r = $record.ToXml()
  
            $h = [ordered]@{
                LogName          = $record.LogName
                RecordType       = $record.LevelDisplayName
                Level            = $record.Level
                LevelDisplayName = $record.LevelDisplayName
                TimeCreated      = $record.TimeCreated
                Id               = $record.Id
            }
  
            if ($r.Event.UserData.HasChildNodes) {
                Write-Verbose "[PROCESS] Parsing event data"
                if ($r.Event.UserData -is [array]) {
                    <#
                 I only want to enumerate with the For loop if the data is an array of objects
                 If the data is just a single string like Foo, then when using the For loop,
                 the data value will be the F and not the complete string, Foo.
                 #>
                    for ($i = 0; $i -lt $r.Event.UserData.count; $i++) {
  
                        $data = $r.Event.UserData[$i]
                        #test if there is structured data or just text
                        if ($data.name) {
                            $Name = $data.name
                            $Value = $data.'#text'
                        }
                        else {
                            Write-Verbose "[PROCESS] No data property name detected"
                            $Name = "RawProperties"
                            #data will likely be an array of strings
                            [string[]]$Value = $data
                        }
  
                        if ($h.Contains("RawProperties")) {
                            Write-Verbose "[PROCESS] Appending to RawProperties"
                            $h.RawProperties += $value
                        }
                        else {
                            Write-Verbose "[PROCESS] Adding $name"
                            $h.add($name, $Value)
                        }
                    } #for data
                } #data is an array
                else {
                    $data = $r.Event.UserData
                    if ($data.name) {
                        $Name = $data.name
                        $Value = $data.InnerXml
                    }
                    else {
                        Write-Verbose "[PROCESS] No data property name detected"
                        $Name = "RawProperties"
                        #data will likely be an array of strings
                        [string[]]$Value = $data
                    }
  
                    if ($h.Contains("RawProperties")) {
                        Write-Verbose "[PROCESS] Appending to RawProperties"
                        $h.RawProperties += $value
                    }
                    else {
                        Write-Verbose "[PROCESS] Adding $name"
                        $h.add($name, $Value)
                    }
                }
            } #if data
            else {
                Write-Verbose "[PROCESS] No event data to process"
            }
  
            $h.Add("Message", $record.Message)
            $h.Add("Keywords", $record.KeywordsDisplayNames)
            $h.Add("Source", $record.ProviderName)
            $h.Add("Computername", $record.MachineName)
  
            Write-Verbose "[PROCESS] Creating custom object"
            New-Object -TypeName PSObject -Property $h
        } #foreach record
    } #process
  
    end {
        Write-Verbose "[END    ] Ending: $($MyInvocation.Mycommand)"
    } #end
}
  
function Format-XML ([xml]$Xml, $Indent = 3) { 
    $StringWriter = New-Object System.IO.StringWriter 
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter 
    $XmlWriter.Formatting = "Indented"
    $XmlWriter.Indentation = $Indent 
    $Xml.WriteContentTo($XmlWriter) 
    $XmlWriter.Flush() 
    $StringWriter.Flush() 
    Write-Output $StringWriter.ToString() 
}

function Get-X509CertificateInfo {
    <#
    .SYNOPSIS
        Extracts certificate information from CAPI2 Event 90 (X509 Objects)
        
    .DESCRIPTION
        Parses Event 90 to extract detailed certificate information including:
        - Subject Common Name (CN)
        - Subject Alternative Names (SANs) - DNS names, UPNs
        - Organization
        - Issuer
        - Serial Number
        - Validity dates
        
    .PARAMETER Events
        Array of CAPI2 events to search for Event 90
        
    .OUTPUTS
        PSCustomObject with certificate details or $null if no Event 90 found
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Events
    )
    
    # Find Event 90 (X509 Objects)
    $Event90 = $Events | Where-Object { $_.ID -eq 90 } | Select-Object -First 1
    
    if (-not $Event90) {
        return $null
    }
    
    try {
        [xml]$EventXml = $Event90.DetailedMessage
        
        # Get all Certificate nodes
        $AllCertNodes = $EventXml.GetElementsByTagName("Certificate")
        
        if (-not $AllCertNodes -or $AllCertNodes.Count -eq 0) {
            return $null
        }
        
        # Prioritize end-entity certificate (the one with SubjectAltName extensions, not a CA)
        $CertNode = $null
        foreach ($cert in $AllCertNodes) {
            # Check if this certificate has SubjectAltName (indicates end-entity cert)
            # Use GetElementsByTagName to handle XML namespaces
            $Extensions = $cert.GetElementsByTagName("Extensions")
            if ($Extensions -and $Extensions.Count -gt 0) {
                $SubjectAltNames = $Extensions[0].GetElementsByTagName("SubjectAltName")
                if ($SubjectAltNames -and $SubjectAltNames.Count -gt 0) {
                    $CertNode = $cert
                    break
                }
            }
        }
        
        # If no cert with SANs found, check for non-CA certificate (cA='false')
        if (-not $CertNode) {
            foreach ($cert in $AllCertNodes) {
                $Extensions = $cert.GetElementsByTagName("Extensions")
                if ($Extensions -and $Extensions.Count -gt 0) {
                    $BasicConstraints = $Extensions[0].GetElementsByTagName("BasicConstraints")
                    if ($BasicConstraints -and $BasicConstraints.Count -gt 0) {
                        $cAValue = $BasicConstraints[0].GetAttribute("cA")
                        if ($cAValue -eq "false") {
                            $CertNode = $cert
                            break
                        }
                    }
                }
            }
        }
        
        # Fallback to first certificate
        if (-not $CertNode) {
            $CertNode = $AllCertNodes | Select-Object -First 1
        }
        
        # Extract Subject CN
        $SubjectCN = $CertNode.GetAttribute("subjectName")
        
        # Extract Subject details
        $SubjectNode = $CertNode.SelectSingleNode("Subject")
        $Organization = ""
        $Country = ""
        
        if ($SubjectNode) {
            $OrgNode = $SubjectNode.SelectSingleNode("O")
            if ($OrgNode) { $Organization = $OrgNode.InnerText }
            
            $CountryNode = $SubjectNode.SelectSingleNode("C")
            if ($CountryNode) { $Country = $CountryNode.InnerText }
        }
        
        # Extract Issuer CN
        $IssuerNode = $CertNode.SelectSingleNode("Issuer/CN")
        $IssuerCN = if ($IssuerNode) { $IssuerNode.InnerText } else { "" }
        
        # Extract Subject Alternative Names (SANs)
        $SANs = @()
        $Extensions = $CertNode.GetElementsByTagName("Extensions")
        if ($Extensions -and $Extensions.Count -gt 0) {
            $SubjectAltNames = $Extensions[0].GetElementsByTagName("SubjectAltName")
            if ($SubjectAltNames -and $SubjectAltNames.Count -gt 0) {
                $SANNode = $SubjectAltNames[0]
                
                # DNS Names
                $DNSNodes = $SANNode.GetElementsByTagName("DNSName")
                foreach ($DNS in $DNSNodes) {
                    $SANs += "DNS: $($DNS.InnerText)"
                }
                
                # UPNs (User Principal Names)
                $UPNNodes = $SANNode.GetElementsByTagName("UPN")
                foreach ($UPN in $UPNNodes) {
                    $SANs += "UPN: $($UPN.InnerText)"
                }
                
                # Email addresses
                $EmailNodes = $SANNode.GetElementsByTagName("RFC822Name")
                foreach ($Email in $EmailNodes) {
                    $SANs += "Email: $($Email.InnerText)"
                }
            }
        }
        
        # Extract Serial Number
        $SerialNode = $CertNode.SelectSingleNode("SerialNumber")
        $SerialNumber = if ($SerialNode) { $SerialNode.InnerText } else { "" }
        
        # Extract Validity dates
        $NotBeforeNode = $CertNode.SelectSingleNode("NotBefore")
        $NotAfterNode = $CertNode.SelectSingleNode("NotAfter")
        $NotBefore = if ($NotBeforeNode) { [DateTime]$NotBeforeNode.InnerText } else { $null }
        $NotAfter = if ($NotAfterNode) { [DateTime]$NotAfterNode.InnerText } else { $null }
        
        # Build certificate info object
        return [PSCustomObject]@{
            SubjectCN    = $SubjectCN
            Organization = $Organization
            Country      = $Country
            IssuerCN     = $IssuerCN
            SANs         = $SANs
            SerialNumber = $SerialNumber
            NotBefore    = $NotBefore
            NotAfter     = $NotAfter
            HasSANs      = ($SANs.Count -gt 0)
        }
    }
    catch {
        Write-Verbose "Could not parse Event 90: $_"
        return $null
    }
}

function Get-EventChainSummary {
    <#
    .SYNOPSIS
        Creates a summary of all events in a CAPI2 correlation chain.
    .PARAMETER Events
        Array of CAPI2 events from the same correlation chain
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Events
    )
    
    # Comprehensive mapping of Event IDs to Task Categories based on CAPI2 documentation
    # Includes all possible CAPI2 Operational log events for complete chain visibility
    $TaskCategoryMap = @{
        # Chain Building
        11  = "Build Chain"
        100 = "Build Chain Context"
        
        # Chain Verification
        30  = "Verify Chain Policy"
        31  = "Verify Chain Policy Result"
        32  = "Chain Policy Context"
        
        # Revocation Checking
        70  = "Verify Revocation"
        71  = "Revocation Status"
        52  = "Retrieve CRL"
        53  = "Retrieve OCSP"
        
        # Certificate Operations
        90  = "X509 Objects"
        10  = "Verify Trust"
        14  = "Certificate Details"
        15  = "Certificate Path"
        
        # Cryptographic Operations
        40  = "Private Key"
        41  = "Sign Hash"
        42  = "Verify Signature"
        
        # CRL/CTL Operations
        50  = "CRL Retrieval"
        51  = "CRL Verification"
        80  = "CTL Operations"
        81  = "CTL Retrieval"
        
        # Chain Context
        1   = "Retrieve Object from Cache"
        2   = "Add Object to Cache"
        3   = "Remove Object from Cache"
        4   = "Cache Flush"
        
        # Network Retrieval
        20  = "Begin Network Retrieval"
        21  = "End Network Retrieval"
        22  = "Network Retrieval Timeout"
        
        # Errors and Warnings
        101 = "Chain Error"
        102 = "Chain Warning"
    }
    
    # Level mapping
    $LevelMap = @{
        0 = "LogAlways"
        1 = "Critical"
        2 = "Error"
        3 = "Warning"
        4 = "Information"
        5 = "Verbose"
    }
    
    $ChainSummary = @()
    
    foreach ($Event in $Events) {
        # Extract sequence number from CorrelationAuxInfo
        $SequenceNum = $null
        try {
            [xml]$EventXml = $Event.DetailedMessage
            
            # Try CorrelationAuxInfo/@SeqNumber (most common, namespace-aware)
            $AuxInfoNode = $EventXml.GetElementsByTagName("CorrelationAuxInfo") | Select-Object -First 1
            if ($AuxInfoNode -and $AuxInfoNode.SeqNumber) {
                $SequenceNum = [int]$AuxInfoNode.SeqNumber
            }
            else {
                # Fallback to EventAuxInfo/@SequenceNumber
                $AuxInfoNode = $EventXml.GetElementsByTagName("EventAuxInfo") | Select-Object -First 1
                if ($AuxInfoNode -and $AuxInfoNode.SequenceNumber) {
                    $SequenceNum = [int]$AuxInfoNode.SequenceNumber
                }
            }
        }
        catch {
            Write-Verbose "Could not parse sequence number for event ID $($Event.Id)"
        }
        
        # Get Level display name
        $LevelDisplay = if ($Event.LevelDisplayName) {
            $Event.LevelDisplayName
        }
        elseif ($null -ne $Event.Level -and $Event.Level -ne "") {
            $LevelMap[[int]$Event.Level]
        }
        else {
            "Information"
        }
        
        # Get Task Category
        $TaskDisplay = if ($Event.TaskDisplayName) {
            $Event.TaskDisplayName
        }
        elseif ($null -ne $Event.Id -and $TaskCategoryMap.ContainsKey($Event.Id)) {
            $TaskCategoryMap[$Event.Id]
        }
        elseif ($null -ne $Event.Id) {
            "Event $($Event.Id)"
        }
        else {
            "Unknown"
        }
        
        $ChainSummary += [PSCustomObject]@{
            Sequence     = $SequenceNum
            TimeCreated  = $Event.TimeCreated
            Level        = $LevelDisplay
            EventID      = if ($null -ne $Event.Id) { $Event.Id } else { "N/A" }
            TaskCategory = $TaskDisplay
        }
    }
    
    # Sort by sequence number if available, otherwise by time
    $ChainSummary = $ChainSummary | Sort-Object -Property @{Expression = { if ($_.Sequence) { $_.Sequence } else { 999999 } } }, TimeCreated
    
    return $ChainSummary
}

#region Analysis and Export Functions

function Get-CapiErrorAnalysis {
    <#
    .SYNOPSIS
        Analyzes CAPI2 events and presents errors in a comprehensive table format.
        
    .DESCRIPTION
        Parses certificate chain building and revocation events, identifies errors,
        and presents them in an easy-to-understand table with descriptions and resolution steps.
        
    .PARAMETER Events
        Array of CAPI2 events from Get-CapiTaskIDEvents or Find-CapiEventsByName
        
    .PARAMETER IncludeSummary
        Shows a summary count of error types
        
    .PARAMETER ShowEventChain
        Displays all events in the CAPI2 correlation chain with their Task Categories (Build Chain, X509 Objects, Verify Chain Policy, etc.)
        Shows the complete event sequence including Event IDs and levels (Information, Error, Warning)
        
    .EXAMPLE
        $Events = Get-CapiTaskIDEvents -TaskID "12345..."
        Get-CapiErrorAnalysis -Events $Events
        
    .EXAMPLE
        $Results = Find-CapiEventsByName -Name "contoso.com"
        Get-CapiErrorAnalysis -Events $Results[0].Events -IncludeSummary
        
    .EXAMPLE
        # Pipeline support - automatically uses .Events property
        Find-CapiEventsByName -Name "expired.badssl.com" | Get-CapiErrorAnalysis -ShowEventChain
        Shows all CAPI2 events in the chain with their categories (Build Chain, X509 Objects, etc.)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [array]$Events,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeSummary,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowEventChain
    )
    
    begin {
        $ErrorTable = @()
        $ErrorSummary = @{}
        $AllEventsAccumulator = @()
    }
    
    process {
        # Handle pipeline input from Find-CapiEventsByName which has .Events property
        $EventsToProcess = if ($Events[0].PSObject.Properties.Name -contains 'Events') {
            # Piped from Find-CapiEventsByName - extract actual events
            $Events | ForEach-Object { $_.Events }
        } else {
            # Direct array of events
            $Events
        }
        
        # Accumulate individual events for use in end block
        foreach ($Event in $EventsToProcess) {
            $AllEventsAccumulator += $Event
        }
        
        foreach ($CurrentEvent in $EventsToProcess) {
            # Parse XML to find error codes
            try {
                [xml]$EventXml = $CurrentEvent.DetailedMessage
                
                # Check for Result elements with error values
                # Only select Result and Error nodes, not other value attributes like Flags
                # Use local-name() to handle XML namespaces
                $ResultNodes = $EventXml.SelectNodes("//*[local-name()='Result' and @value] | //*[local-name()='Error' and @value]")
                
                foreach ($Node in $ResultNodes) {
                    $ErrorValue = $Node.value
                    
                    # Skip success codes
                    if ($ErrorValue -eq "0" -or $ErrorValue -eq "0x0") {
                        continue
                    }
                    
                    # Get error details
                    $ErrorDetails = Get-CAPI2ErrorDetails -ErrorCode $ErrorValue
                    
                    # Extract certificate information
                    $CertSubject = "(not available)"
                    $CertIssuer = ""
                    $CertThumbprint = "(not available)"
                    
                    $CertNode = $EventXml.SelectSingleNode("//Certificate[@subjectName]")
                    if ($CertNode) {
                        $CertSubject = $CertNode.subjectName
                        # Extract thumbprint from fileRef attribute (format: "THUMBPRINT.cer")
                        if ($CertNode.fileRef) {
                            $CertThumbprint = $CertNode.fileRef -replace '\.cer$', ''
                        }
                    }
                    
                    $IssuerNode = $EventXml.SelectSingleNode("//IssuerCertificate[@subjectName]")
                    if ($IssuerNode) {
                        $CertIssuer = $IssuerNode.subjectName
                    }
                    
                    # Extract process name
                    $ProcessName = ""
                    $ProcessNode = $EventXml.SelectSingleNode("//EventAuxInfo[@ProcessName]")
                    if ($ProcessNode) {
                        $ProcessName = $ProcessNode.ProcessName
                    }
                    
                    # Parse TrustStatus information (chain-level and per-certificate)
                    $TrustStatusInfo = $null
                    $ChainTrustStatus = $EventXml.SelectSingleNode("//*[local-name()='CertificateChain']/*[local-name()='TrustStatus']")
                    if ($ChainTrustStatus) {
                        $TrustStatusInfo = Get-TrustStatusDetails -TrustStatusNode $ChainTrustStatus
                    }
                    
                    # Create error entry
                    $ErrorEntry = [PSCustomObject]@{
                        TimeCreated = $CurrentEvent.TimeCreated
                        EventID     = $CurrentEvent.ID
                        Severity    = $ErrorDetails.Severity
                        ErrorCode   = $ErrorDetails.Code
                        ErrorName   = $ErrorDetails.HexCode
                        Description = $ErrorDetails.Description
                        Certificate = $CertSubject
                        Thumbprint  = $CertThumbprint
                        Issuer      = $CertIssuer
                        Process     = $ProcessName
                        CommonCause = $ErrorDetails.CommonCause
                        Resolution  = $ErrorDetails.Resolution
                        TrustStatus = $TrustStatusInfo
                    }
                    
                    $ErrorTable += $ErrorEntry
                    
                    # Count for summary
                    if ($ErrorSummary.ContainsKey($ErrorDetails.HexCode)) {
                        $ErrorSummary[$ErrorDetails.HexCode]++
                    }
                    else {
                        $ErrorSummary[$ErrorDetails.HexCode] = 1
                    }
                }
            }
            catch {
                Write-Verbose "Could not parse event ID $($CurrentEvent.ID): $_"
            }
        }
    }
    
    end {
        # Extract X509 certificate information from Event 90 and display at top
        $CertInfo = Get-X509CertificateInfo -Events $AllEventsAccumulator
        
        if ($CertInfo) {
            Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
            Write-Host "║           Certificate Information (Event 90)                  ║" -ForegroundColor Cyan
            Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
            Write-Host "  Subject CN:      " -NoNewline -ForegroundColor Gray
            Write-Host "$($CertInfo.SubjectCN)" -ForegroundColor White
            
            if ($CertInfo.Organization) {
                Write-Host "  Organization:    " -NoNewline -ForegroundColor Gray
                Write-Host "$($CertInfo.Organization)" -ForegroundColor White
            }
            
            if ($CertInfo.Country) {
                Write-Host "  Country:         " -NoNewline -ForegroundColor Gray
                Write-Host "$($CertInfo.Country)" -ForegroundColor White
            }
            
            if ($CertInfo.IssuerCN) {
                Write-Host "  Issued By:       " -NoNewline -ForegroundColor Gray
                Write-Host "$($CertInfo.IssuerCN)" -ForegroundColor White
            }
            
            if ($CertInfo.HasSANs) {
                Write-Host "  SANs:            " -NoNewline -ForegroundColor Gray
                $FirstSAN = $true
                foreach ($SAN in $CertInfo.SANs) {
                    if ($FirstSAN) {
                        Write-Host "$SAN" -ForegroundColor Cyan
                        $FirstSAN = $false
                    }
                    else {
                        Write-Host "                   $SAN" -ForegroundColor Cyan
                    }
                }
            }
            
            if ($CertInfo.SerialNumber) {
                Write-Host "  Serial:          " -NoNewline -ForegroundColor Gray
                Write-Host "$($CertInfo.SerialNumber)" -ForegroundColor DarkGray
            }
            
            if ($CertInfo.NotBefore -and $CertInfo.NotAfter) {
                Write-Host "  Valid:           " -NoNewline -ForegroundColor Gray
                $Now = Get-Date
                $ValidityColor = if ($Now -lt $CertInfo.NotBefore) { "Yellow" } 
                elseif ($Now -gt $CertInfo.NotAfter) { "Red" }
                else { "Green" }
                Write-Host "$($CertInfo.NotBefore.ToString('yyyy-MM-dd')) to $($CertInfo.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor $ValidityColor
            }
            Write-Host ""
        }
        
        # Display event chain if requested
        if ($ShowEventChain -and $AllEventsAccumulator.Count -gt 0) {
            Write-Host "`n=== CAPI2 Correlation Chain Events ===" -ForegroundColor Cyan
            Write-Host "Total events in chain: $($AllEventsAccumulator.Count)" -ForegroundColor Gray
            Write-Host "Events are sorted by AuxInfo sequence number`n" -ForegroundColor Gray
            
            $ChainSummary = Get-EventChainSummary -Events $AllEventsAccumulator
            $ChainSummary | Format-Table -Property Sequence, TimeCreated, Level, EventID, TaskCategory -AutoSize
        }
        
        if ($ErrorTable.Count -eq 0) {
            if ($ShowEventChain) {
                Write-Host "`n$(Get-DisplayChar 'Checkmark') No errors found in the certificate validation chain!" -ForegroundColor Green
                Write-Host "  All certificate operations completed successfully." -ForegroundColor Gray
            }
            else {
                Write-Host "`n$(Get-DisplayChar 'Checkmark') No errors found in the certificate validation chain!" -ForegroundColor Green
                Write-Host "  All certificate operations completed successfully." -ForegroundColor Gray
            }
            return
        }
        
        Write-Host "`n=== CAPI2 Error Analysis ===" -ForegroundColor Cyan
        Write-Host "Found $($ErrorTable.Count) error(s) in the certificate validation chain.`n" -ForegroundColor Yellow
        
        # Display detailed error table
        $ErrorTable | Format-Table -Property TimeCreated, Severity, ErrorName, Certificate, Thumbprint, Description -AutoSize -Wrap
        
        Write-Host "`n=== Detailed Error Information ===" -ForegroundColor Cyan
        
        foreach ($ErrorEntry in $ErrorTable) {
            Write-Host "`n[$($ErrorEntry.Severity)] $($ErrorEntry.ErrorName) - $($ErrorEntry.ErrorCode)" -ForegroundColor $(
                switch ($ErrorEntry.Severity) {
                    "Critical" { "Red" }
                    "Error" { "Red" }
                    "Warning" { "Yellow" }
                    default { "White" }
                }
            )
            Write-Host "  Certificate:   $($ErrorEntry.Certificate)" -ForegroundColor Gray
            if ($ErrorEntry.Thumbprint) {
                Write-Host "  Thumbprint:    $($ErrorEntry.Thumbprint)" -ForegroundColor Gray
            }
            if ($ErrorEntry.Issuer) {
                Write-Host "  Issuer:        $($ErrorEntry.Issuer)" -ForegroundColor Gray
            }
            Write-Host "  Description:   $($ErrorEntry.Description)" -ForegroundColor White
            Write-Host "  Common Cause:  $($ErrorEntry.CommonCause)" -ForegroundColor Yellow
            Write-Host "  Resolution:    $($ErrorEntry.Resolution)" -ForegroundColor Green
            
            # Display TrustStatus details if available
            if ($ErrorEntry.TrustStatus) {
                $Trust = $ErrorEntry.TrustStatus
                
                if ($Trust.ErrorFlags.Count -gt 0) {
                    Write-Host "`n  Trust Chain Validation Errors:" -ForegroundColor Red
                    foreach ($Flag in $Trust.ErrorFlags) {
                        $FlagColor = switch ($Flag.Severity) {
                            'Critical' { 'Red' }
                            'Error' { 'Red' }
                            'Warning' { 'Yellow' }
                            default { 'White' }
                        }
                        Write-Host "    $(Get-DisplayChar 'Warning') [$($Flag.Severity)] $($Flag.Flag)" -ForegroundColor $FlagColor
                        Write-Host "       $($Flag.Description)" -ForegroundColor Gray
                    }
                }
                
                if ($Trust.InfoFlags.Count -gt 0) {
                    Write-Host "`n  Trust Chain Information:" -ForegroundColor Cyan
                    foreach ($Flag in $Trust.InfoFlags) {
                        Write-Host "    $(Get-DisplayChar 'Checkmark') $($Flag.Flag)" -ForegroundColor Gray
                        Write-Host "       $($Flag.Description)" -ForegroundColor DarkGray
                    }
                }
            }
        }
        
        # Display summary if requested
        if ($IncludeSummary) {
            Write-Host "`n=== Error Summary ===" -ForegroundColor Cyan
            $ErrorSummary.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
                Write-Host "  $($_.Key): $($_.Value) occurrence(s)" -ForegroundColor White
            }
        }
        
        # Return the error table for further processing
        return $ErrorTable
    }
}

function Export-CapiEvents {
    <#
    .SYNOPSIS
        Exports CAPI2 events to various formats (CSV, JSON, HTML, XML).
        
    .DESCRIPTION
        Exports certificate validation events to file for analysis, reporting, or archival.
        Supports multiple output formats with optional error analysis.
        
    .PARAMETER Events
        Array of CAPI2 events to export
        
    .PARAMETER Path
        Output file path or directory path.
        - If a directory: Filename is auto-generated as "CapiEvents_<TaskID>.<ext>"
        - If a file path: Uses the specified filename and extension
        - Extension determines format: .csv, .json, .html, .xml (if Format not specified)
        
    .PARAMETER Format
        Explicitly specify output format (CSV, JSON, HTML, XML)
        Overrides extension-based detection. Required when Path is a directory.
        
    .PARAMETER IncludeErrorAnalysis
        Include error analysis in the export
        
    .PARAMETER TaskID
        TaskID associated with these events (for reference in export)
        Used in auto-generated filenames when Path is a directory.
        
    .EXAMPLE
        $Events = Get-CapiTaskIDEvents -TaskID "12345..."
        Export-CapiEvents -Events $Events -Path "C:\Reports" -Format CSV -TaskID "12345..."
        # Creates: C:\Reports\CapiEvents_12345678.csv
        
    .EXAMPLE
        $Results = Find-CapiEventsByName -Name "contoso.com"
        Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports" -Format HTML -IncludeErrorAnalysis -TaskID $Results[0].TaskID
        
    .EXAMPLE
        Export-CapiEvents -Events $Events -Path "C:\Reports" -Format JSON -TaskID "12345..."
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [array]$Events,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('CSV', 'JSON', 'HTML', 'XML')]
        [string]$Format,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeErrorAnalysis,
        
        [Parameter(Mandatory = $false)]
        [string]$TaskID
    )
    
    begin {
        # Determine if Path is a directory or file
        $IsDirectory = $false
        if (Test-Path -Path $Path -PathType Container) {
            $IsDirectory = $true
        }
        elseif (-not [System.IO.Path]::HasExtension($Path)) {
            # Path doesn't exist and has no extension, treat as directory
            $IsDirectory = $true
        }
        
        # Determine format
        if (-not $Format) {
            if ($IsDirectory) {
                # Default to HTML if directory specified
                $Format = 'HTML'
            }
            else {
                # Determine from file extension
                $Extension = [System.IO.Path]::GetExtension($Path).ToLower()
                $Format = switch ($Extension) {
                    '.csv' { 'CSV' }
                    '.json' { 'JSON' }
                    '.html' { 'HTML' }
                    '.xml' { 'XML' }
                    default { 'CSV' }
                }
            }
        }
        
        # Construct filename if Path is a directory
        if ($IsDirectory) {
            # Create directory if it doesn't exist
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force | Out-Null
            }
            
            # Build filename: CapiEvents_<ShortTaskID>.<extension>
            $ShortTaskID = if ($TaskID) { $TaskID.Substring(0, 8) } else { (Get-Date -Format 'yyyyMMdd_HHmmss') }
            $Extension = switch ($Format) {
                'CSV' { 'csv' }
                'JSON' { 'json' }
                'HTML' { 'html' }
                'XML' { 'xml' }
                default { 'txt' }
            }
            $FileName = "CapiEvents_$ShortTaskID.$Extension"
            $Path = Join-Path $Path $FileName
        }
        
        Write-Host "Exporting $($Events.Count) event(s) to $Format format..." -ForegroundColor Cyan
    }
    
    process {
        try {
            # Prepare data for export
            $ExportData = $Events | Select-Object TimeCreated, ID, RecordType, 
            @{N = 'EventName'; E = {
                    if ($_.DetailedMessage -match '<(\w+)\s') { $matches[1] } else { 'Unknown' }
                }
            },
            @{N = 'Certificate'; E = {
                    if ($_.DetailedMessage -match 'subjectName="([^"]+)"') { $matches[1] } else { $null }
                }
            },
            @{N = 'Details'; E = { $_.DetailedMessage } }
            
            switch ($Format) {
                'CSV' {
                    $ExportData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                }
                'JSON' {
                    $JsonData = @{
                        TaskID     = $TaskID
                        ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        EventCount = $Events.Count
                        Events     = $ExportData
                    }
                    
                    if ($IncludeErrorAnalysis) {
                        $ErrorAnalysis = Get-CapiErrorAnalysis -Events $Events
                        
                        # Filter out non-informative errors (same logic as HTML)
                        $FilteredErrors = $ErrorAnalysis | Where-Object {
                            -not ($_.Certificate -eq "(not available)" -and 
                                $_.Thumbprint -eq "(not available)" -and
                                (-not $_.TrustStatus -or 
                                ($_.TrustStatus.ErrorFlags.Count -eq 0 -and $_.TrustStatus.InfoFlags.Count -eq 0)))
                        }
                        
                        $JsonData['ErrorAnalysis'] = $FilteredErrors
                        $JsonData['ErrorCount'] = $FilteredErrors.Count
                    }
                    
                    $JsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                }
                'XML' {
                    $XmlData = @{
                        TaskID     = $TaskID
                        ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Events     = $ExportData
                    }
                    
                    if ($IncludeErrorAnalysis) {
                        $ErrorAnalysis = Get-CapiErrorAnalysis -Events $Events
                        
                        # Filter out non-informative errors (same logic as HTML/JSON)
                        $FilteredErrors = $ErrorAnalysis | Where-Object {
                            -not ($_.Certificate -eq "(not available)" -and 
                                $_.Thumbprint -eq "(not available)" -and
                                (-not $_.TrustStatus -or 
                                ($_.TrustStatus.ErrorFlags.Count -eq 0 -and $_.TrustStatus.InfoFlags.Count -eq 0)))
                        }
                        
                        $XmlData['ErrorAnalysis'] = $FilteredErrors
                        $XmlData['ErrorCount'] = $FilteredErrors.Count
                    }
                    
                    $XmlData | Export-Clixml -Path $Path
                }
                'HTML' {
                    # Extract X509 certificate information from Event 90
                    $CertInfo = Get-X509CertificateInfo -Events $Events
                    
                    # Build certificate info HTML section
                    $CertInfoHtml = ""
                    if ($CertInfo) {
                        $CertInfoHtml = @"
    <div class="info" style="background: #f0f9ff; border-left: 4px solid #0078d4;">
        <h3 style="margin-top: 0; color: #0078d4;">📜 Certificate Details (Event 90 - X509 Objects)</h3>
        <table style="box-shadow: none; margin-top: 10px;">
            <tr><td style="font-weight: bold; width: 150px;">Subject CN:</td><td>$($CertInfo.SubjectCN)</td></tr>
$(if ($CertInfo.Organization) { "            <tr><td style='font-weight: bold;'>Organization:</td><td>$($CertInfo.Organization)</td></tr>`n" })$(if ($CertInfo.Country) { "            <tr><td style='font-weight: bold;'>Country:</td><td>$($CertInfo.Country)</td></tr>`n" })$(if ($CertInfo.IssuerCN) { "            <tr><td style='font-weight: bold;'>Issued By:</td><td>$($CertInfo.IssuerCN)</td></tr>`n" })$(if ($CertInfo.HasSANs) {
    $SANsHtml = ($CertInfo.SANs | ForEach-Object { "<li>$_</li>" }) -join ""
    "            <tr><td style='font-weight: bold;'>SANs:</td><td><ul style='margin: 5px 0; padding-left: 20px;'>$SANsHtml</ul></td></tr>`n"
})$(if ($CertInfo.SerialNumber) { "            <tr><td style='font-weight: bold;'>Serial Number:</td><td style='font-family: monospace; font-size: 0.9em;'>$($CertInfo.SerialNumber)</td></tr>`n" })$(if ($CertInfo.NotBefore -and $CertInfo.NotAfter) {
    $Now = Get-Date
    $ValidityStatus = if ($Now -lt $CertInfo.NotBefore) { "⚠️ Not yet valid" } 
                     elseif ($Now -gt $CertInfo.NotAfter) { "❌ Expired" }
                     else { "✅ Valid" }
    $ValidityColor = if ($Now -lt $CertInfo.NotBefore) { "color: #ff8c00;" } 
                    elseif ($Now -gt $CertInfo.NotAfter) { "color: #d13438;" }
                    else { "color: #107c10;" }
    "            <tr><td style='font-weight: bold;'>Validity Period:</td><td><span style='$ValidityColor'>$ValidityStatus</span> ($($CertInfo.NotBefore.ToString('yyyy-MM-dd')) to $($CertInfo.NotAfter.ToString('yyyy-MM-dd')))</td></tr>`n"
})        </table>
    </div>
"@
                    }
                    
                    $HtmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>CAPI2 Event Analysis Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #106ebe; margin-top: 30px; }
        h3 { color: #0078d4; margin-bottom: 10px; }
        .info { background: #e7f3ff; padding: 15px; border-left: 4px solid #0078d4; margin: 20px 0; }
        .cert-name { font-size: 1.2em; color: #0078d4; font-weight: bold; margin-bottom: 10px; }
        table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background: #0078d4; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .error { color: #d13438; font-weight: bold; }
        .warning { color: #ff8c00; }
        .success { color: #107c10; }
        .timestamp { color: #666; font-size: 0.9em; }
        pre { background: #f0f0f0; padding: 10px; overflow-x: auto; border-left: 3px solid #666; }
    </style>
</head>
<body>
    <h1>🔐 CAPI2 Certificate Validation Report</h1>
    <div class="info">
        <strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
        <strong>TaskID:</strong> $TaskID<br>
        <strong>Event Count:</strong> $($Events.Count)
    </div>
$CertInfoHtml
"@
                    
                    if ($IncludeErrorAnalysis) {
                        $ErrorAnalysis = Get-CapiErrorAnalysis -Events $Events
                        if ($ErrorAnalysis) {
                            $HtmlReport += "<h2>❌ Error Analysis</h2>"
                            
                            # Build custom HTML table with TrustStatus details
                            $HtmlReport += @"
<table>
    <thead>
        <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Error</th>
            <th>Certificate</th>
            <th>Thumbprint</th>
            <th>Description</th>
            <th>Trust Chain Details</th>
        </tr>
    </thead>
    <tbody>
"@
                            foreach ($ErrorEntry in $ErrorAnalysis) {
                                # Skip errors without useful information
                                # Check if certificate is missing or placeholder
                                $HasNoCert = (-not $ErrorEntry.Certificate) -or 
                                ($ErrorEntry.Certificate -eq "(not available)") -or
                                ($ErrorEntry.Certificate -eq "")
                                            
                                # Check if thumbprint is missing or placeholder  
                                $HasNoThumb = (-not $ErrorEntry.Thumbprint) -or
                                ($ErrorEntry.Thumbprint -eq "(not available)") -or
                                ($ErrorEntry.Thumbprint -eq "")
                                             
                                # Check if TrustStatus has useful data
                                $HasNoTrust = (-not $ErrorEntry.TrustStatus) -or
                                (($ErrorEntry.TrustStatus.ErrorFlags.Count -eq 0) -and 
                                ($ErrorEntry.TrustStatus.InfoFlags.Count -eq 0))
                                
                                # Skip if ALL three are empty/useless
                                if ($HasNoCert -and $HasNoThumb -and $HasNoTrust) {
                                    Write-Verbose "Skipping non-informative error: $($ErrorEntry.ErrorName)"
                                    continue
                                }
                                
                                $SeverityClass = switch ($ErrorEntry.Severity) {
                                    'Critical' { 'error' }
                                    'Error' { 'error' }
                                    'Warning' { 'warning' }
                                    default { '' }
                                }
                                
                                # Build TrustStatus HTML
                                $TrustHtml = ""
                                if ($ErrorEntry.TrustStatus) {
                                    if ($ErrorEntry.TrustStatus.ErrorFlags.Count -gt 0) {
                                        $TrustHtml += "<div style='margin-top: 5px;'><strong style='color: #d13438;'>Trust Errors:</strong><ul style='margin: 5px 0; padding-left: 20px;'>"
                                        foreach ($Flag in $ErrorEntry.TrustStatus.ErrorFlags) {
                                            $TrustHtml += "<li><strong>$($Flag.Flag)</strong><br><span style='color: #666; font-size: 0.9em;'>$($Flag.Description)</span></li>"
                                        }
                                        $TrustHtml += "</ul></div>"
                                    }
                                    if ($ErrorEntry.TrustStatus.InfoFlags.Count -gt 0) {
                                        $TrustHtml += "<div style='margin-top: 5px;'><strong style='color: #0078d4;'>Trust Info:</strong><ul style='margin: 5px 0; padding-left: 20px; font-size: 0.9em;'>"
                                        foreach ($Flag in $ErrorEntry.TrustStatus.InfoFlags) {
                                            $TrustHtml += "<li style='color: #666;'>$($Flag.Flag)</li>"
                                        }
                                        $TrustHtml += "</ul></div>"
                                    }
                                }
                                if (-not $TrustHtml) {
                                    $TrustHtml = "<span style='color: #999;'>No chain details</span>"
                                }
                                
                                # Format Certificate and Thumbprint for display
                                $CertDisplay = if ($ErrorEntry.Certificate -and $ErrorEntry.Certificate -ne "(not available)") { 
                                    $ErrorEntry.Certificate 
                                }
                                else { 
                                    "<span style='color: #999; font-style: italic;'>Not available</span>" 
                                }
                                
                                $ThumbprintDisplay = if ($ErrorEntry.Thumbprint -and $ErrorEntry.Thumbprint -ne "(not available)") { 
                                    $ErrorEntry.Thumbprint 
                                }
                                else { 
                                    "<span style='color: #999; font-style: italic;'>N/A</span>" 
                                }
                                
                                $HtmlReport += @"
        <tr>
            <td class='timestamp'>$($ErrorEntry.TimeCreated)</td>
            <td class='$SeverityClass'>$($ErrorEntry.Severity)</td>
            <td><strong>$($ErrorEntry.ErrorName)</strong></td>
            <td>$CertDisplay</td>
            <td style='font-family: monospace; font-size: 0.85em;'>$ThumbprintDisplay</td>
            <td>$($ErrorEntry.Description)<br><br><strong>Resolution:</strong> $($ErrorEntry.Resolution)</td>
            <td>$TrustHtml</td>
        </tr>
"@
                            }
                            $HtmlReport += @"
    </tbody>
</table>
"@
                            
                            # Add resolution guidance section
                            $HtmlReport += @"
<h2>🔧 Resolution Guidance</h2>
<div class='info'>
    <p><strong>When errors are found in CAPI2 correlation chains:</strong></p>
    <ol>
        <li><strong>Review Error Details:</strong> Check the error name and description in the Error Analysis table above</li>
        <li><strong>Check Certificate Status:</strong> Verify certificate validity, expiration, and trust chain</li>
        <li><strong>Verify Certificate Store:</strong> Ensure required root/intermediate certificates are installed</li>
        <li><strong>Check Revocation:</strong> Confirm CRL/OCSP endpoints are accessible if revocation errors occur</li>
        <li><strong>Review Time Settings:</strong> Ensure system clock is accurate for time-based validations</li>
        <li><strong>Examine Network Access:</strong> Verify connectivity to certificate authorities and OCSP responders</li>
        <li><strong>Use Correlation Chain:</strong> Review all events in the chain below to understand the validation flow</li>
    </ol>
    <p><strong>PowerShell Commands for Troubleshooting:</strong></p>
    <pre>Get-CapiErrorAnalysis -Events <dollarsign>Events -IncludeSummary
Compare-CapiEvents -ReferenceEvents <dollarsign>Before -DifferenceEvents <dollarsign>After
Get-CAPI2EventLogStatus</pre>
</div>
"@
                        }
                        else {
                            $HtmlReport += @"
<h2>✅ Validation Status</h2>
<div class='info' style='background: #e7ffe7; border-left-color: #107c10;'>
    <p style='color: #107c10; font-weight: bold;'>✓ All certificate validation operations completed successfully!</p>
    <p>No errors were detected in the CAPI2 correlation chain. The certificate chain is trusted and all validation checks passed.</p>
</div>
"@
                        }
                    }
                    
                    # Add CAPI2 Correlation Chain Events table
                    $HtmlReport += "<h2>📋 CAPI2 Correlation Chain Events</h2>"
                    $HtmlReport += "<div class='info'>"
                    $HtmlReport += "<p><strong>Total events in correlation chain:</strong> $($Events.Count)</p>"
                    $HtmlReport += "<p>This section shows all CAPI2 events sorted by AuxInfo sequence number, displaying the exact order of the certificate validation process.</p>"
                    $HtmlReport += "</div>"
                    
                    $ChainSummary = Get-EventChainSummary -Events $Events
                    $HtmlReport += @"
<table>
    <thead>
        <tr>
            <th>Seq</th>
            <th>Time</th>
            <th>Level</th>
            <th>Event ID</th>
            <th>Task Category</th>
        </tr>
    </thead>
    <tbody>
"@
                    foreach ($ChainEvent in $ChainSummary) {
                        $LevelClass = switch ($ChainEvent.Level) {
                            'Error' { 'error' }
                            'Warning' { 'warning' }
                            'Information' { '' }
                            default { '' }
                        }
                        
                        $SeqDisplay = if ($ChainEvent.Sequence) { $ChainEvent.Sequence } else { "-" }
                        
                        $HtmlReport += @"
        <tr>
            <td style='text-align: center; font-weight: bold; color: #666;'>$SeqDisplay</td>
            <td class='timestamp'>$($ChainEvent.TimeCreated)</td>
            <td class='$LevelClass'>$($ChainEvent.Level)</td>
            <td>$($ChainEvent.EventID)</td>
            <td>$($ChainEvent.TaskCategory)</td>
        </tr>
"@
                    }
                    $HtmlReport += @"
    </tbody>
</table>
"@
                    
                    $HtmlReport += "<h2>Event Details</h2>"
                    $HtmlReport += $ExportData | ConvertTo-Html -Fragment -Property TimeCreated, ID, RecordType, EventName, Certificate
                    $HtmlReport += "</body></html>"
                    
                    $HtmlReport | Out-File -FilePath $Path -Encoding UTF8
                }
            }
            
            Write-Host "$(Get-DisplayChar 'Checkmark') Export completed successfully: $Path" -ForegroundColor Green
            Write-Host "  Format: $Format | Size: $([math]::Round((Get-Item $Path).Length / 1KB, 2)) KB" -ForegroundColor Gray
            
        }
        catch {
            Write-Error "Failed to export events: $($_.Exception.Message)"
        }
    }
}

function Compare-CapiEvents {
    <#
    .SYNOPSIS
        Compares two CAPI2 event correlation chains to identify changes or resolved errors.
        
    .DESCRIPTION
        Compares certificate validation chains from different time periods to determine
        if errors have been resolved or new issues have appeared.
        
    .PARAMETER ReferenceEvents
        The original/baseline events (e.g., from when error occurred)
        
    .PARAMETER DifferenceEvents
        The new events to compare against (e.g., after attempted fix)
        
    .PARAMETER ReferenceLabel
        Label for reference events (default: "Before")
        
    .PARAMETER DifferenceLabel
        Label for difference events (default: "After")
        
    .EXAMPLE
        # Capture baseline
        $Before = Get-CapiTaskIDEvents -TaskID "12345..."
        # Make changes, test again
        $After = Get-CapiTaskIDEvents -TaskID "67890..."
        Compare-CapiEvents -ReferenceEvents $Before -DifferenceEvents $After
        
    .EXAMPLE
        $Results1 = Find-CapiEventsByName -Name "contoso.com"
        # Fix configuration
        $Results2 = Find-CapiEventsByName -Name "contoso.com"
        Compare-CapiEvents -ReferenceEvents $Results1[0].Events -DifferenceEvents $Results2[0].Events
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ReferenceEvents,
        
        [Parameter(Mandatory = $true)]
        [array]$DifferenceEvents,
        
        [Parameter(Mandatory = $false)]
        [string]$ReferenceLabel = "Before",
        
        [Parameter(Mandatory = $false)]
        [string]$DifferenceLabel = "After"
    )
    
    Write-Host "`n=== CAPI2 Event Comparison ===" -ForegroundColor Cyan
    Write-Host "$ReferenceLabel Events: $($ReferenceEvents.Count) - $DifferenceLabel Events: $($DifferenceEvents.Count)`n" -ForegroundColor White
    
    # Get error analysis for both sets
    Write-Host "Analyzing $ReferenceLabel events..." -ForegroundColor Gray
    $ReferenceErrors = Get-CapiErrorAnalysis -Events $ReferenceEvents
    
    Write-Host "Analyzing $DifferenceLabel events..." -ForegroundColor Gray
    $DifferenceErrors = Get-CapiErrorAnalysis -Events $DifferenceEvents
    
    # Compare error counts
    $RefErrorCount = if ($ReferenceErrors) { $ReferenceErrors.Count } else { 0 }
    $DiffErrorCount = if ($DifferenceErrors) { $DifferenceErrors.Count } else { 0 }
    
    Write-Host "`n=== Comparison Results ===" -ForegroundColor Cyan
    
    if ($RefErrorCount -eq 0 -and $DiffErrorCount -eq 0) {
        Write-Host "$(Get-DisplayChar 'Checkmark') No errors in either event set - All validations successful!" -ForegroundColor Green
        return
    }
    
    if ($RefErrorCount -gt 0 -and $DiffErrorCount -eq 0) {
        Write-Host "$(Get-DisplayChar 'Checkmark') ERRORS RESOLVED!" -ForegroundColor Green
        Write-Host "  $ReferenceLabel had $RefErrorCount error(s), $DifferenceLabel has 0 errors." -ForegroundColor Green
        Write-Host "`nResolved Errors:" -ForegroundColor Green
        $ReferenceErrors | Format-Table ErrorName, Certificate, Description -AutoSize
        return
    }
    
    if ($RefErrorCount -eq 0 -and $DiffErrorCount -gt 0) {
        Write-Host "$(Get-DisplayChar 'Warning') NEW ERRORS DETECTED!" -ForegroundColor Red
        Write-Host "  $ReferenceLabel had 0 errors, $DifferenceLabel has $DiffErrorCount error(s)." -ForegroundColor Red
        Write-Host "`nNew Errors:" -ForegroundColor Red
        $DifferenceErrors | Format-Table ErrorName, Certificate, Description -AutoSize
        return
    }
    
    # Both have errors - find differences
    Write-Host "Error Count: $ReferenceLabel = $RefErrorCount, $DifferenceLabel = $DiffErrorCount" -ForegroundColor Yellow
    
    $RefErrorTypes = $ReferenceErrors | Select-Object -ExpandProperty ErrorName -Unique
    $DiffErrorTypes = $DifferenceErrors | Select-Object -ExpandProperty ErrorName -Unique
    
    $ResolvedErrors = $RefErrorTypes | Where-Object { $_ -notin $DiffErrorTypes }
    $NewErrors = $DiffErrorTypes | Where-Object { $_ -notin $RefErrorTypes }
    $PersistentErrors = $RefErrorTypes | Where-Object { $_ -in $DiffErrorTypes }
    
    if ($ResolvedErrors) {
        Write-Host "`n$(Get-DisplayChar 'Checkmark') Resolved Errors:" -ForegroundColor Green
        $ResolvedErrors | ForEach-Object {
            $ErrorDetail = $ReferenceErrors | Where-Object { $_.ErrorName -eq $_ } | Select-Object -First 1
            Write-Host "  - $_ : $($ErrorDetail.Description)" -ForegroundColor Green
        }
    }
    
    if ($NewErrors) {
        Write-Host "`n$(Get-DisplayChar 'Warning') New Errors:" -ForegroundColor Red
        $NewErrors | ForEach-Object {
            $ErrorDetail = $DifferenceErrors | Where-Object { $_.ErrorName -eq $_ } | Select-Object -First 1
            Write-Host "  - $_ : $($ErrorDetail.Description)" -ForegroundColor Red
        }
    }
    
    if ($PersistentErrors) {
        Write-Host "`n$(Get-DisplayChar 'Warning') Persistent Errors (still present):" -ForegroundColor Yellow
        $PersistentErrors | ForEach-Object {
            $ErrorDetail = $DifferenceErrors | Where-Object { $_.ErrorName -eq $_ } | Select-Object -First 1
            Write-Host "  - $_ : $($ErrorDetail.Description)" -ForegroundColor Yellow
        }
    }
    
    # Summary
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Resolved: $($ResolvedErrors.Count) | New: $($NewErrors.Count) | Persistent: $($PersistentErrors.Count)" -ForegroundColor White
    
    if ($DiffErrorCount -lt $RefErrorCount) {
        Write-Host "`n$(Get-DisplayChar 'Checkmark') Overall improvement: Error count reduced from $RefErrorCount to $DiffErrorCount" -ForegroundColor Green
    }
    elseif ($DiffErrorCount -gt $RefErrorCount) {
        Write-Host "`n$(Get-DisplayChar 'Warning') Situation worsened: Error count increased from $RefErrorCount to $DiffErrorCount" -ForegroundColor Red
    }
    else {
        $ErrorText = "$RefErrorCount errors"
        Write-Host "`n$(Get-DisplayChar 'RightArrow') No change in error count - $ErrorText" -ForegroundColor Yellow
    }
}

#endregion

#region Simplified Workflow Functions

function Get-CapiCertificateReport {
    <#
    .SYNOPSIS
        Simplified one-command solution to find, analyze, and export certificate errors.
        
    .DESCRIPTION
        This function combines search, error analysis, and export into a single command.
        Perfect for quickly diagnosing certificate validation issues without writing complex scripts.
        
        The function will:
        1. Search for certificate events by name (searches SubjectAltName, CN, ProcessName, and more)
        2. Automatically analyze errors if found
        3. Optionally export results to HTML, JSON, CSV, or XML
        4. Display a summary of findings
        
    .PARAMETER Name
        DNS name, certificate subject (CN/SubjectAltName), process name, or issuer to search for.
        Automatically searches across multiple fields: subjectName, CN, SubjectAltName/DNSName, ProcessName.
        Supports wildcards for flexible matching.
        
    .PARAMETER ExportPath
        Directory path where reports will be saved. Each correlation chain will be exported to a separate file.
        File names are automatically generated based on certificate subject name and TaskID.
        Example: "C:\Reports" or "./reports"
        If multiple chains are found, files like "microsoft.com_621E9428.html" will be created.
        
    .PARAMETER Format
        Export format for the reports.
        Valid options: HTML, JSON, CSV, XML
        Default: HTML
        
    .PARAMETER Hours
        How many hours to look back in the event log (default: 24, max: 8760)
        Valid range: 1 to 8760 hours (1 year)
        
    .PARAMETER ShowDetails
        Display detailed error information in the console (in addition to any export)
        
    .PARAMETER OpenReport
        Automatically open Windows Explorer to show the exported reports directory
        Requires -ExportPath to be specified
        Opens the directory containing all exported files for easy access
        
    .EXAMPLE
        Get-CapiCertificateReport -Name "expired.badssl.com"
        Search for expired.badssl.com events and display error analysis
        
    .EXAMPLE
        Get-CapiCertificateReport -Name "microsoft.com" -ExportPath "C:\Reports"
        Find microsoft.com events, analyze errors, and export to C:\Reports\microsoft.com_<TaskID>.html
        
    .EXAMPLE
        Get-CapiCertificateReport -Name "*.contoso.com" -ExportPath "C:\Reports" -Format JSON -OpenReport
        Find all contoso.com subdomains, export each to separate JSON files, and open Explorer to show reports
        
    .EXAMPLE
        Get-CapiCertificateReport -Name "*microsoft.com" -ExportPath "C:\temp" -Hours 5 -ShowDetails -Format HTML
        Search for microsoft.com in last 5 hours, export all chains to separate HTML files in C:\temp
        
    .EXAMPLE
        Get-CapiCertificateReport -Name "badssl" -Hours 2 -ShowDetails -ExportPath "badssl_errors.json"
        Search last 2 hours for badssl events, show detailed analysis, and export to JSON
        
    .EXAMPLE
        Get-CapiCertificateReport -Name "chrome.exe" -Hours 4
        Find all certificate validations made by Chrome in the last 4 hours
        
    .EXAMPLE
        Get-CapiCertificateReport -Name "GlobalSecureAccessClient.exe" -ExportPath "gsa_report.html"
        Find all certificate validations by Global Secure Access Client and export to HTML
        
    .NOTES
        This is the recommended function for most users. It simplifies the workflow from:
          $Results = Find-CapiEventsByName -Name "site.com"
          Get-CapiErrorAnalysis -Events $Results[0].Events
          Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports" -Format HTML -TaskID $Results[0].TaskID
        To just:
          Get-CapiCertificateReport -Name "site.com" -ExportPath "C:\Reports" -Format HTML
          
        When multiple correlation chains are found, each is exported to a separate file:
          - C:\Reports\site.com_621E9428.html
          - C:\Reports\site.com_4E61DCEE.html
          - etc.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('HTML', 'JSON', 'CSV', 'XML')]
        [string]$Format = 'HTML',
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 8760)]
        [int]$Hours = 24,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowDetails,
        
        [Parameter(Mandatory = $false)]
        [switch]$OpenReport
    )
    
    # Validate that OpenReport requires ExportPath
    if ($OpenReport -and -not $ExportPath) {
        Write-Error "-OpenReport switch requires -ExportPath to be specified"
        return
    }
    
    # Validate and create export directory if specified
    if ($ExportPath) {
        if (-not (Test-Path $ExportPath)) {
            try {
                New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
                Write-Host "$(Get-DisplayChar 'Lightbulb') Created export directory: $ExportPath" -ForegroundColor Gray
            }
            catch {
                Write-Error "Failed to create export directory: $ExportPath. Error: $_"
                return
            }
        }
        elseif (-not (Test-Path $ExportPath -PathType Container)) {
            Write-Error "ExportPath must be a directory, not a file: $ExportPath"
            return
        }
    }
    
    Write-Host "`n$(Get-DisplayChar 'RightArrow') Searching for certificate events: $Name" -ForegroundColor Cyan
    Write-Host "   Time range: Last $Hours hours`n" -ForegroundColor Gray
    
    # Search for events
    $Results = Find-CapiEventsByName -Name $Name -Hours $Hours
    
    if (-not $Results -or $Results.Count -eq 0) {
        Write-Host "$(Get-DisplayChar 'Warning') No certificate events found for: $Name" -ForegroundColor Yellow
        Write-Host "`nTroubleshooting tips:" -ForegroundColor Cyan
        Write-Host "  1. Verify CAPI2 logging is enabled: " -NoNewline -ForegroundColor Gray
        Write-Host "Get-CAPI2EventLogStatus" -ForegroundColor White
        Write-Host "  2. Reproduce the certificate issue (browse to site, run application)" -ForegroundColor Gray
        Write-Host "  3. Try a broader search term or increase -Hours parameter" -ForegroundColor Gray
        Write-Host "  4. Use Start-CAPI2Troubleshooting to prepare for fresh testing`n" -ForegroundColor Gray
        return
    }
    
    # Display summary
    Write-Host "$(Get-DisplayChar 'CheckmarkBold') Found $($Results.Count) correlation chain(s) matching '$Name'" -ForegroundColor Green
    Write-Host ""
    
    # Track exported files
    $ExportedFiles = @()
    
    # Process each chain
    $ChainNumber = 0
    foreach ($Chain in $Results) {
        $ChainNumber++
        
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Chain #$ChainNumber of $($Results.Count)" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  TaskID: " -NoNewline -ForegroundColor Gray
        Write-Host $Chain.TaskID -ForegroundColor White
        Write-Host "  Timestamp: " -NoNewline -ForegroundColor Gray
        Write-Host $Chain.Timestamp -ForegroundColor White
        Write-Host "  Events: " -NoNewline -ForegroundColor Gray
        Write-Host $Chain.Events.Count -ForegroundColor White
        
        # Count errors
        $ErrorEvents = $Chain.Events | Where-Object { $_.Id -eq 30 }
        $ErrorCount = if ($ErrorEvents) { $ErrorEvents.Count } else { 0 }
        
        Write-Host "  Errors: " -NoNewline -ForegroundColor Gray
        if ($ErrorCount -eq 0) {
            Write-Host $ErrorCount -ForegroundColor Green
        }
        else {
            Write-Host $ErrorCount -ForegroundColor Red
        }
        
        # Extract certificate name for filename
        $CertificateName = "Unknown"
        try {
            foreach ($Event in $Chain.Events) {
                [xml]$EventXml = $Event.DetailedMessage
                
                # Try subjectName attribute first
                $CertNode = $EventXml.SelectSingleNode("//*[@subjectName]")
                if ($CertNode -and $CertNode.subjectName) {
                    $CertificateName = $CertNode.subjectName
                    break
                }
                
                # Try CN element
                $CNNode = $EventXml.SelectSingleNode("//CN")
                if ($CNNode -and $CNNode.InnerText) {
                    $CertificateName = $CNNode.InnerText
                    break
                }
                
                # Try ProcessName
                $ProcessNode = $EventXml.SelectSingleNode("//*[@ProcessName]")
                if ($ProcessNode -and $ProcessNode.ProcessName) {
                    $CertificateName = $ProcessNode.ProcessName -replace '\.exe$', ''
                    break
                }
            }
        }
        catch {
            # If extraction fails, use search name
            $CertificateName = $Name -replace '[*?]', ''
        }
        
        # Sanitize certificate name for filename
        $SafeCertName = $CertificateName -replace '[\\/:*?"<>|]', '_'
        
        Write-Host "  Certificate: " -NoNewline -ForegroundColor Gray
        Write-Host $CertificateName -ForegroundColor White
        Write-Host ""
        
        # Always show error analysis for the first chain, or all if ShowDetails
        if ($ChainNumber -eq 1 -or $ShowDetails) {
            Get-CapiErrorAnalysis -Events $Chain.Events -IncludeSummary
        }
        
        # Export each chain if path provided
        if ($ExportPath) {
            # Get short TaskID (first 8 chars)
            $ShortTaskID = $Chain.TaskID.ToString().Substring(0, 8)
            
            # Determine file extension
            $Extension = switch ($Format) {
                'HTML' { '.html' }
                'JSON' { '.json' }
                'CSV' { '.csv' }
                'XML' { '.xml' }
                default { '.html' }
            }
            
            # Build filename: CertName_TaskID.ext
            $FileName = "${SafeCertName}_${ShortTaskID}${Extension}"
            $FullExportPath = Join-Path $ExportPath $FileName
            
            Write-Host "$(Get-DisplayChar 'RightArrow') Exporting to: " -NoNewline -ForegroundColor Cyan
            Write-Host $FileName -ForegroundColor White
            
            # Export
            Export-CapiEvents -Events $Chain.Events -Path $FullExportPath -Format $Format -IncludeErrorAnalysis -TaskID $Chain.TaskID
            
            $ExportedFiles += $FullExportPath
        }
        
        Write-Host ""
    }
    
    # Final summary
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  $(Get-DisplayChar 'CheckmarkBold') Certificate Report Complete" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    
    if ($ExportedFiles.Count -gt 0) {
        Write-Host "  Exported $($ExportedFiles.Count) report(s) to: " -NoNewline -ForegroundColor Gray
        Write-Host $ExportPath -ForegroundColor White
        
        if ($ExportedFiles.Count -le 5) {
            # Show all files if 5 or fewer
            foreach ($File in $ExportedFiles) {
                Write-Host "    - " -NoNewline -ForegroundColor Gray
                Write-Host ([System.IO.Path]::GetFileName($File)) -ForegroundColor Cyan
            }
        }
        else {
            # Show first 3 and last 1 if more than 5
            for ($i = 0; $i -lt 3; $i++) {
                Write-Host "    - " -NoNewline -ForegroundColor Gray
                Write-Host ([System.IO.Path]::GetFileName($ExportedFiles[$i])) -ForegroundColor Cyan
            }
            Write-Host "    ... and $($ExportedFiles.Count - 4) more files ..." -ForegroundColor Gray
            Write-Host "    - " -NoNewline -ForegroundColor Gray
            Write-Host ([System.IO.Path]::GetFileName($ExportedFiles[-1])) -ForegroundColor Cyan
        }
        
        # Open Explorer to show the reports directory if requested
        if ($OpenReport) {
            Write-Host ""
            Write-Host "$(Get-DisplayChar 'RightArrow') Opening Explorer to show reports..." -ForegroundColor Cyan
            Start-Process "explorer.exe" -ArgumentList $ExportPath
        }
    }
    
    Write-Host ""
}#endregion

#region Workflow Helper Functions

function Start-CAPI2Troubleshooting {
    <#
    .SYNOPSIS
        Prepares the CAPI2 event log for a fresh troubleshooting session.
        
    .DESCRIPTION
        This workflow cmdlet enables CAPI2 logging and optionally clears existing events.
        Use this before reproducing a certificate issue to ensure clean event data.
        Requires administrative privileges.
        
    .PARAMETER ClearLog
        Clears existing CAPI2 events before starting
        
    .PARAMETER BackupPath
        If specified with -ClearLog, backs up existing events before clearing
        
    .EXAMPLE
        Start-CAPI2Troubleshooting
        Enables CAPI2 logging
        
    .EXAMPLE
        Start-CAPI2Troubleshooting -ClearLog
        Enables logging and clears existing events
        
    .EXAMPLE
        Start-CAPI2Troubleshooting -ClearLog -BackupPath "C:\Logs\CAPI2_Before_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
        Enables logging, backs up existing events, and clears log
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$ClearLog,
        
        [Parameter(Mandatory = $false)]
        [string]$BackupPath
    )
    
    Write-BoxHeader -Text "Starting CAPI2 Troubleshooting Session" -Icon "Wrench" -Color Cyan
    
    # Check admin rights
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsAdmin) {
        Write-Error "This cmdlet requires administrative privileges. Please run PowerShell as Administrator."
        return
    }
    
    # Step 1: Enable logging
    Write-Host "[Step 1/3] Enabling CAPI2 Event Log..." -ForegroundColor Yellow
    Enable-CAPI2EventLog
    
    # Step 2: Clear log if requested
    if ($ClearLog) {
        Write-Host "`n[Step 2/3] Clearing CAPI2 Event Log..." -ForegroundColor Yellow
        if ($BackupPath) {
            Clear-CAPI2EventLog -Backup $BackupPath
        }
        else {
            Clear-CAPI2EventLog
        }
    }
    else {
        Write-Host "`n[Step 2/3] Keeping existing events (use -ClearLog to clear)" -ForegroundColor Gray
    }
    
    # Step 3: Show status
    Write-Host "`n[Step 3/3] Current CAPI2 Log Status:" -ForegroundColor Yellow
    Get-CAPI2EventLogStatus
    
    Write-Host "`n$(Get-DisplayChar 'CheckmarkBold') CAPI2 Troubleshooting Session Ready!" -ForegroundColor Green
    Write-Host "   Next steps:" -ForegroundColor White
    Write-Host "   1. Reproduce your certificate issue (browse to site, run application, etc.)" -ForegroundColor Gray
    Write-Host "   2. Use Find-CapiEventsByName to locate events: Find-CapiEventsByName -Name 'yoursite.com'" -ForegroundColor Gray
    Write-Host "   3. Analyze errors: Get-CapiErrorAnalysis -Events `$Results[0].Events" -ForegroundColor Gray
    Write-Host "   4. When done, run: Stop-CAPI2Troubleshooting`n" -ForegroundColor Gray
}

function Stop-CAPI2Troubleshooting {
    <#
    .SYNOPSIS
        Completes the CAPI2 troubleshooting session and optionally disables logging.
        
    .DESCRIPTION
        This workflow cmdlet provides a summary of the troubleshooting session and
        optionally disables CAPI2 logging to reduce log volume.
        Requires administrative privileges.
        
    .PARAMETER DisableLog
        Disables CAPI2 logging after showing summary
        
    .PARAMETER ExportPath
        If specified, exports all recent events to the specified path before disabling
        
    .EXAMPLE
        Stop-CAPI2Troubleshooting
        Shows summary without disabling logging
        
    .EXAMPLE
        Stop-CAPI2Troubleshooting -DisableLog
        Shows summary and disables CAPI2 logging
        
    .EXAMPLE
        Stop-CAPI2Troubleshooting -DisableLog -ExportPath "C:\Reports\CAPI2_Session_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
        Exports events, shows summary, and disables logging
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DisableLog,
        
        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )
    
    Write-BoxHeader -Text "Completing CAPI2 Troubleshooting Session" -Icon "Flag" -Color Cyan
    
    # Check admin rights
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsAdmin) {
        Write-Error "This cmdlet requires administrative privileges. Please run PowerShell as Administrator."
        return
    }
    
    # Show final status
    Write-Host "[Step 1/3] Final CAPI2 Log Status:" -ForegroundColor Yellow
    Get-CAPI2EventLogStatus
    
    # Export if requested
    if ($ExportPath) {
        Write-Host "`n[Step 2/3] Exporting CAPI2 Event Log..." -ForegroundColor Yellow
        try {
            wevtutil.exe epl Microsoft-Windows-CAPI2/Operational "$ExportPath"
            if ($LASTEXITCODE -eq 0) {
                Write-Host "$(Get-DisplayChar 'Checkmark') Events exported to: $ExportPath" -ForegroundColor Green
            }
            else {
                Write-Warning "Failed to export events. Exit code: $LASTEXITCODE"
            }
        }
        catch {
            Write-Warning "Error exporting events: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "`n[Step 2/3] No export requested (use -ExportPath to save events)" -ForegroundColor Gray
    }
    
    # Disable if requested
    Write-Host "`n[Step 3/3] CAPI2 Logging..." -ForegroundColor Yellow
    if ($DisableLog) {
        Disable-CAPI2EventLog
    }
    else {
        Write-Host "  Logging remains ENABLED (use -DisableLog to disable)" -ForegroundColor Gray
    }
    
    Write-Host "`n$(Get-DisplayChar 'CheckmarkBold') CAPI2 Troubleshooting Session Complete!" -ForegroundColor Green
    Write-Host "   Recommended next steps:" -ForegroundColor White
    Write-Host "   - Review exported events or analysis reports" -ForegroundColor Gray
    Write-Host "   - Document findings and solutions" -ForegroundColor Gray
    Write-Host "   - If issue persists, compare before/after using Compare-CapiEvents`n" -ForegroundColor Gray
}

#endregion

#region Aliases

# Create friendly aliases for common commands
New-Alias -Name 'Find-CertEvents' -Value 'Find-CapiEventsByName' -Description 'Alias for Find-CapiEventsByName'
New-Alias -Name 'Get-CertChain' -Value 'Get-CapiTaskIDEvents' -Description 'Alias for Get-CapiTaskIDEvents'
New-Alias -Name 'Enable-CapiLog' -Value 'Enable-CAPI2EventLog' -Description 'Alias for Enable-CAPI2EventLog'
New-Alias -Name 'Disable-CapiLog' -Value 'Disable-CAPI2EventLog' -Description 'Alias for Disable-CAPI2EventLog'
New-Alias -Name 'Clear-CapiLog' -Value 'Clear-CAPI2EventLog' -Description 'Alias for Clear-CAPI2EventLog'

#endregion

# Export module members
Export-ModuleMember -Function Find-CapiEventsByName, Get-CapiTaskIDEvents, Convert-EventLogRecord, Format-XML, `
    Enable-CAPI2EventLog, Disable-CAPI2EventLog, Clear-CAPI2EventLog, Get-CAPI2EventLogStatus, `
    Get-CapiErrorAnalysis, Export-CapiEvents, Compare-CapiEvents, Get-CAPI2ErrorDetails, `
    Get-CapiCertificateReport, Start-CAPI2Troubleshooting, Stop-CAPI2Troubleshooting `
    -Alias 'Find-CertEvents', 'Get-CertChain', 'Enable-CapiLog', 'Disable-CapiLog', 'Clear-CapiLog'

<#
.NOTES
    Version:        2.5
    Author:         Jan Tiedemann
    Creation Date:  2022
    Last Modified:  December 2025
    Purpose:        CAPI2 Event Log Correlation Analysis Toolkit
    
    Changes in v2.5:
    - Added comprehensive error analysis with human-readable descriptions
    - Added CAPI2 error code translation with resolution steps
    - Added event log management (Enable/Disable/Clear/Status)
    - Added export functionality (CSV, JSON, HTML, XML)
    - Added comparison feature to track error resolution
    - Enhanced error tables with severity, causes, and resolutions
    
    Changes in v2.0:
    - Added Find-CapiEventsByName for DNS/Certificate name-based searching
    - Enhanced documentation and help text
    - Improved error handling and user feedback
    - Added color-coded console output
    - Removed deprecated Search-InUserData function
    
.EXAMPLE
    # Enable CAPI2 logging before troubleshooting
    Enable-CAPI2EventLog
    Get-CAPI2EventLogStatus
    
    # Clear log for fresh start
    Clear-CAPI2EventLog -Backup "C:\Logs\CAPI2_Backup.evtx"
    
    # Search by DNS/Certificate name (no TaskID needed)
    $Results = Find-CapiEventsByName -Name "microsoft.com"
    
    # Analyze errors with detailed descriptions
    Get-CapiErrorAnalysis -Events $Results[0].Events -IncludeSummary
    
    # Export to various formats
    Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports" -Format HTML -IncludeErrorAnalysis -TaskID $Results[0].TaskID
    Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports" -Format JSON -TaskID $Results[0].TaskID
    
    # Compare before/after fixing
    $Before = Get-CapiTaskIDEvents -TaskID "GUID-BEFORE"
    # Apply fix, then test again
    $After = Get-CapiTaskIDEvents -TaskID "GUID-AFTER"
    Compare-CapiEvents -ReferenceEvents $Before -DifferenceEvents $After
    
    # Traditional method: Direct TaskID lookup
    Get-CapiTaskIDEvents -TaskID "7E11B6A3-50EA-47ED-928D-BBE4784EFA3F"
    
    # Disable logging when done
    Disable-CAPI2EventLog
#>

