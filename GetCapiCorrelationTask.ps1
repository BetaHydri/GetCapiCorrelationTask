
<#PSScriptInfo

.VERSION 2.5

.GUID 3228f1cd-8cca-4839-b9aa-7c93c83a917e

.AUTHOR Jan Tiedemann

.COMPANYNAME Jan Tiedemann

.COPYRIGHT GNU GENERAL PUBLIC LICENSE v3

.TAGS CAPI2, EventLog, Certificate, TLS, SSL, Correlation, Troubleshooting

.LICENSEURI https://www.gnu.org/licenses/gpl-3.0.en.html

.PROJECTURI https://github.com/BetaHydri/GetCapiCorrelationTask

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
Version 2.5: Added error analysis tables, export functions, comparison features, CAPI2 log management
Version 2.0: Added DNS/Certificate name filtering, enhanced search capabilities
Version 1.0: Initial release with TaskID-based correlation

.PRIVATEDATA

#>

<# 

.DESCRIPTION 
 Gets the CAPI2 Operational Logs based on correlation (TaskID) or by filtering DNS/Certificate names.
 This enhanced version allows administrators to find certificate chains without knowing the TaskID beforehand.

#> 

#Param()

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
    if ($ErrorCode -match '^[0-9]+$') {
        $ErrorCode = "0x{0:X8}" -f [int64]$ErrorCode
    }
    
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
                Write-Host "✓ CAPI2 Event Log successfully enabled." -ForegroundColor Green
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
                Write-Host "✓ CAPI2 Event Log successfully disabled." -ForegroundColor Green
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
                    Write-Host "✓ Backup completed successfully." -ForegroundColor Green
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
                Write-Host "✓ CAPI2 Event Log successfully cleared." -ForegroundColor Green
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
        
        $LogDetails = wevtutil.exe gl Microsoft-Windows-CAPI2/Operational
        
        # Parse log details
        $Enabled = if ($LogDetails -match "enabled:\s+(\w+)") { $matches[1] } else { "Unknown" }
        $LogMode = if ($LogDetails -match "logFileName:\s+(.+)") { $matches[1] } else { "Unknown" }
        $MaxSize = if ($LogDetails -match "maxSize:\s+(\d+)") { [math]::Round($matches[1] / 1MB, 2) } else { "Unknown" }
        
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
            Write-Host "💡 Tip: Run 'Enable-CAPI2EventLog' to enable certificate event logging." -ForegroundColor Yellow
        }
        
        if ($EventCount -eq 0) {
            Write-Host "💡 Tip: No events found. Perform certificate operations to generate events." -ForegroundColor Yellow
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
          Searches CAPI2 events by DNS name or certificate subject name and retrieves all correlated events.
            
      .DESCRIPTION
          This function allows administrators to find certificate validation chains by searching for a DNS name 
          or certificate subject without needing to know the TaskID beforehand. It searches the CAPI2 log,
          identifies all TaskIDs associated with the specified name, and retrieves all correlated events.
            
      .PARAMETER Name
          The DNS name or certificate subject name to search for (e.g., "bing.com", "*.microsoft.com", "DigiCert")
          Supports wildcard matching.
       
      .PARAMETER MaxEvents
          Maximum number of events to retrieve for initial search (default: 1000)
          
      .PARAMETER Hours
          Number of hours to look back in the event log (default: 24)
          
      .PARAMETER IncludePattern
          If specified, only returns events matching this pattern in the certificate details
          
      .EXAMPLE
          Find-CapiEventsByName -Name "bing.com"
          Finds all CAPI2 correlation chains for bing.com
      
      .EXAMPLE
          Find-CapiEventsByName -Name "*.microsoft.com" -Hours 48
          Finds all Microsoft-related certificate chains in the last 48 hours
          
      .EXAMPLE
          Find-CapiEventsByName -Name "DigiCert" -IncludePattern "revocation"
          Finds DigiCert certificates with revocation-related events
      
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
        $IncludePattern
    )
    
    begin {
        Write-Verbose "[BEGIN  ] Starting: $($MyInvocation.Mycommand)"
        $StartTime = (Get-Date).AddHours(-$Hours)
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
            $MatchingTaskIDs = $ConvertedEvents | Where-Object {
                $EventXml = $_.UserData
                if ($null -ne $EventXml) {
                    $XmlString = $EventXml.ToString()
                    # Check for subjectName, DNSName, CN, or other certificate identifiers
                    if ($XmlString -like $WildcardPattern) {
                        if ($IncludePattern) {
                            $XmlString -like "*$IncludePattern*"
                        }
                        else {
                            $true
                        }
                    }
                }
            } | ForEach-Object {
                # Extract TaskID from the event
                try {
                    [xml]$EventXml = $_.UserData
                    $TaskIdNode = $EventXml.SelectSingleNode("//*[@TaskId]")
                    if ($null -ne $TaskIdNode) {
                        $TaskId = $TaskIdNode.TaskId
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
                    Write-Verbose "Could not extract TaskID from event: $_"
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
        $Query = "*[UserData[CertVerifyCertificateChainPolicy[CorrelationAuxInfo[@TaskId='{$TaskID}']]]] or 
        *[UserData[CertGetCertificateChain[CorrelationAuxInfo[@TaskId='{$TaskID}']]]] or
        *[UserData[CertGetCertificateChainStart[CorrelationAuxInfo[@TaskId='{$TaskID}']]]] or
        *[UserData[X509Objects[CorrelationAuxInfo[@TaskId='{$TaskID}']]]] or
        *[UserData[CertRejectedRevocationInfo[CorrelationAuxInfo[@TaskId='{$TaskID}']]]] or
        *[UserData[CertVerifyRevocation[CorrelationAuxInfo[@TaskId='{$TaskID}']]]] or
        *[UserData[CertVerifyRevocationStart[CorrelationAuxInfo[@TaskId='{$TaskID}']]]] or
        *[UserData[CryptRetrieveObjectByUrlCache[CorrelationAuxInfo[@TaskId='{$TaskID}']]]] or
        *[UserData[CryptRetrieveObjectByUrlCacheStart[CorrelationAuxInfo[@TaskId='{$TaskID}']]]]"
  
        $Events = Get-WinEvent -FilterXPath $Query -LogName Microsoft-Windows-CAPI2/Operational -ErrorAction SilentlyContinue | Convert-EventLogRecord | Select-Object -Property TimeCreated, Id, RecordType, @{N = 'DetailedMessage'; E = { (Format-XML $_.UserData) } } | Sort-Object -Property TimeCreated 
        if ($null -ne $Events) {
            return $Events
        }
        else {
            Write-Host "No Capi2 Event were found with the CorrelationID $TaskID" -ForegroundColor Yellow
            exit
        }
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
                LogName     = $record.LogName
                RecordType  = $record.LevelDisplayName
                TimeCreated = $record.TimeCreated
                ID          = $record.Id
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
        
    .EXAMPLE
        $Events = Get-CapiTaskIDEvents -TaskID "12345..."
        Get-CapiErrorAnalysis -Events $Events
        
    .EXAMPLE
        $Results = Find-CapiEventsByName -Name "contoso.com"
        Get-CapiErrorAnalysis -Events $Results[0].Events -IncludeSummary
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [array]$Events,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeSummary
    )
    
    begin {
        $ErrorTable = @()
        $ErrorSummary = @{}
    }
    
    process {
        foreach ($Event in $Events) {
            # Parse XML to find error codes
            try {
                [xml]$EventXml = "<root>$($Event.DetailedMessage)</root>"
                
                # Check for Result elements with error values
                $ResultNodes = $EventXml.SelectNodes("//*[@value]")
                
                foreach ($Node in $ResultNodes) {
                    $ErrorValue = $Node.value
                    
                    # Skip success codes
                    if ($ErrorValue -eq "0" -or $ErrorValue -eq "0x0") {
                        continue
                    }
                    
                    # Get error details
                    $ErrorDetails = Get-CAPI2ErrorDetails -ErrorCode $ErrorValue
                    
                    # Extract certificate information
                    $CertSubject = ""
                    $CertIssuer = ""
                    
                    $CertNode = $EventXml.SelectSingleNode("//Certificate[@subjectName]")
                    if ($CertNode) {
                        $CertSubject = $CertNode.subjectName
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
                    
                    # Create error entry
                    $ErrorEntry = [PSCustomObject]@{
                        TimeCreated = $Event.TimeCreated
                        EventID     = $Event.ID
                        Severity    = $ErrorDetails.Severity
                        ErrorCode   = $ErrorDetails.Code
                        ErrorName   = $ErrorDetails.HexCode
                        Description = $ErrorDetails.Description
                        Certificate = $CertSubject
                        Issuer      = $CertIssuer
                        Process     = $ProcessName
                        CommonCause = $ErrorDetails.CommonCause
                        Resolution  = $ErrorDetails.Resolution
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
                Write-Verbose "Could not parse event ID $($Event.ID): $_"
            }
        }
    }
    
    end {
        if ($ErrorTable.Count -eq 0) {
            Write-Host "`n✓ No errors found in the certificate validation chain!" -ForegroundColor Green
            Write-Host "  All certificate operations completed successfully." -ForegroundColor Gray
            return
        }
        
        Write-Host "`n=== CAPI2 Error Analysis ===" -ForegroundColor Cyan
        Write-Host "Found $($ErrorTable.Count) error(s) in the certificate validation chain.`n" -ForegroundColor Yellow
        
        # Display detailed error table
        $ErrorTable | Format-Table -Property TimeCreated, Severity, ErrorName, Certificate, Description -AutoSize -Wrap
        
        Write-Host "`n=== Detailed Error Information ===" -ForegroundColor Cyan
        
        foreach ($Error in $ErrorTable) {
            Write-Host "`n[$($Error.Severity)] $($Error.ErrorName) - $($Error.ErrorCode)" -ForegroundColor $(
                switch ($Error.Severity) {
                    "Critical" { "Red" }
                    "Error" { "Red" }
                    "Warning" { "Yellow" }
                    default { "White" }
                }
            )
            Write-Host "  Certificate:   $($Error.Certificate)" -ForegroundColor Gray
            if ($Error.Issuer) {
                Write-Host "  Issuer:        $($Error.Issuer)" -ForegroundColor Gray
            }
            Write-Host "  Description:   $($Error.Description)" -ForegroundColor White
            Write-Host "  Common Cause:  $($Error.CommonCause)" -ForegroundColor Yellow
            Write-Host "  Resolution:    $($Error.Resolution)" -ForegroundColor Green
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
        Output file path (extension determines format: .csv, .json, .html, .xml)
        
    .PARAMETER Format
        Explicitly specify output format (CSV, JSON, HTML, XML)
        
    .PARAMETER IncludeErrorAnalysis
        Include error analysis in the export
        
    .PARAMETER TaskID
        TaskID associated with these events (for reference in export)
        
    .EXAMPLE
        $Events = Get-CapiTaskIDEvents -TaskID "12345..."
        Export-CapiEvents -Events $Events -Path "C:\Reports\CAPI_Analysis.csv"
        
    .EXAMPLE
        $Results = Find-CapiEventsByName -Name "contoso.com"
        Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports\cert_chain.html" -IncludeErrorAnalysis
        
    .EXAMPLE
        Export-CapiEvents -Events $Events -Path "C:\Reports\events.json" -Format JSON
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
        # Determine format from file extension if not specified
        if (-not $Format) {
            $Extension = [System.IO.Path]::GetExtension($Path).ToLower()
            $Format = switch ($Extension) {
                '.csv' { 'CSV' }
                '.json' { 'JSON' }
                '.html' { 'HTML' }
                '.xml' { 'XML' }
                default { 'CSV' }
            }
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
                    if ($_.DetailedMessage -match 'subjectName="([^"]+)"') { $matches[1] } else { '' }
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
                        $JsonData['ErrorAnalysis'] = $ErrorAnalysis
                    }
                    
                    $JsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                }
                'XML' {
                    $XmlData = @{
                        TaskID     = $TaskID
                        ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Events     = $ExportData
                    }
                    
                    $XmlData | Export-Clixml -Path $Path
                }
                'HTML' {
                    $HtmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>CAPI2 Event Analysis Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #106ebe; margin-top: 30px; }
        .info { background: #e7f3ff; padding: 15px; border-left: 4px solid #0078d4; margin: 20px 0; }
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
"@
                    
                    if ($IncludeErrorAnalysis) {
                        $ErrorAnalysis = Get-CapiErrorAnalysis -Events $Events
                        if ($ErrorAnalysis) {
                            $HtmlReport += "<h2>⚠️ Error Analysis</h2>"
                            $HtmlReport += $ErrorAnalysis | ConvertTo-Html -Fragment -Property TimeCreated, Severity, ErrorName, Certificate, Description, Resolution
                        }
                    }
                    
                    $HtmlReport += "<h2>📋 Event Details</h2>"
                    $HtmlReport += $ExportData | ConvertTo-Html -Fragment -Property TimeCreated, ID, RecordType, EventName, Certificate
                    $HtmlReport += "</body></html>"
                    
                    $HtmlReport | Out-File -FilePath $Path -Encoding UTF8
                }
            }
            
            Write-Host "✓ Export completed successfully: $Path" -ForegroundColor Green
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
    Write-Host "$ReferenceLabel Events: $($ReferenceEvents.Count) | $DifferenceLabel Events: $($DifferenceEvents.Count)`n" -ForegroundColor White
    
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
        Write-Host "✓ No errors in either event set - All validations successful!" -ForegroundColor Green
        return
    }
    
    if ($RefErrorCount -gt 0 -and $DiffErrorCount -eq 0) {
        Write-Host "✓ ERRORS RESOLVED!" -ForegroundColor Green
        Write-Host "  $ReferenceLabel had $RefErrorCount error(s), $DifferenceLabel has 0 errors." -ForegroundColor Green
        Write-Host "`nResolved Errors:" -ForegroundColor Green
        $ReferenceErrors | Format-Table ErrorName, Certificate, Description -AutoSize
        return
    }
    
    if ($RefErrorCount -eq 0 -and $DiffErrorCount -gt 0) {
        Write-Host "⚠️ NEW ERRORS DETECTED!" -ForegroundColor Red
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
        Write-Host "`n✓ Resolved Errors:" -ForegroundColor Green
        $ResolvedErrors | ForEach-Object {
            $ErrorDetail = $ReferenceErrors | Where-Object { $_.ErrorName -eq $_ } | Select-Object -First 1
            Write-Host "  - $_ : $($ErrorDetail.Description)" -ForegroundColor Green
        }
    }
    
    if ($NewErrors) {
        Write-Host "`n⚠️ New Errors:" -ForegroundColor Red
        $NewErrors | ForEach-Object {
            $ErrorDetail = $DifferenceErrors | Where-Object { $_.ErrorName -eq $_ } | Select-Object -First 1
            Write-Host "  - $_ : $($ErrorDetail.Description)" -ForegroundColor Red
        }
    }
    
    if ($PersistentErrors) {
        Write-Host "`n⚠️ Persistent Errors (still present):" -ForegroundColor Yellow
        $PersistentErrors | ForEach-Object {
            $ErrorDetail = $DifferenceErrors | Where-Object { $_.ErrorName -eq $_ } | Select-Object -First 1
            Write-Host "  - $_ : $($ErrorDetail.Description)" -ForegroundColor Yellow
        }
    }
    
    # Summary
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Resolved: $($ResolvedErrors.Count) | New: $($NewErrors.Count) | Persistent: $($PersistentErrors.Count)" -ForegroundColor White
    
    if ($DiffErrorCount -lt $RefErrorCount) {
        Write-Host "`n✓ Overall improvement: Error count reduced from $RefErrorCount to $DiffErrorCount" -ForegroundColor Green
    }
    elseif ($DiffErrorCount -gt $RefErrorCount) {
        Write-Host "`n⚠️ Situation worsened: Error count increased from $RefErrorCount to $DiffErrorCount" -ForegroundColor Red
    }
    else {
        Write-Host "`n→ No change in error count ($RefErrorCount errors)" -ForegroundColor Yellow
    }
}

#endregion

# Export module members
Export-ModuleMember -Function Find-CapiEventsByName, Get-CapiTaskIDEvents, Convert-EventLogRecord, Format-XML, `
    Enable-CAPI2EventLog, Disable-CAPI2EventLog, Clear-CAPI2EventLog, Get-CAPI2EventLogStatus, `
    Get-CapiErrorAnalysis, Export-CapiEvents, Compare-CapiEvents

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
    Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports\cert_analysis.html" -IncludeErrorAnalysis
    Export-CapiEvents -Events $Results[0].Events -Path "C:\Reports\events.json"
    
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

