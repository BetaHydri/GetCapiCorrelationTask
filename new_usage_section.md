---

## 📖 Usage & Troubleshooting Workflows

### 🚀 Quick Start

The fastest way to diagnose certificate issues:

```powershell
# One command - complete analysis with HTML report
Get-CapiCertificateReport -Name "site.contoso.com" -ExportPath "C:\Reports\analysis.html"

# Quick console-only check
Get-CapiCertificateReport -Name "mail.contoso.com"
```

**What it does automatically**:
✅ Searches CAPI2 event log  
✅ Retrieves complete event chains  
✅ Analyzes errors with resolutions  
✅ Displays formatted output  
✅ Exports HTML report (if ExportPath specified)

**Example Output:**
```
=== CAPI2 Certificate Error Analysis ===
Certificate: CN=site.contoso.com
Total Errors: 2
Critical: 1 | Error: 1

ErrorCode  ErrorName         Certificate           Resolution
---------  ---------         -----------           ----------
0x800B0101 CERT_E_EXPIRED    CN=site.contoso.com   1. Renew certificate immediately...
0x800B010A CERT_E_CHAINING   CN=Contoso Inter CA   1. Download intermediate certificate...

HTML report saved: C:\Reports\analysis.html
```

---

### 🔧 Workflow 1: Expired Certificate

**Symptoms**: SSL/TLS errors, authentication failures, applications cannot connect

**Diagnosis**:
```powershell
# Check for expired certificates
Find-CapiEventsByName -Name "*.contoso.com" -FilterType Expired -Hours 24 | 
    Get-CapiErrorAnalysis
```

**Resolution Steps**:
```powershell
# 1. Identify all expired certificates
$Expired = Find-CapiEventsByName -Name "*" -FilterType Expired -Hours 168
$Analysis = Get-CapiErrorAnalysis -Events $Expired[0].Events
$Analysis | Format-Table Certificate, Thumbprint, NotAfter -AutoSize

# 2. Renew certificates
# - Request new certificate via CA, certreq, or Let's Encrypt
# - Install renewed certificate
# - Bind to service (IIS, Exchange, etc.)

# 3. Verify fix
Start-Sleep -Seconds 60
$AfterFix = Find-CapiEventsByName -Name "old.contoso.com" -FilterType Expired -Hours 1
if (-not $AfterFix) {
    Write-Host "✓ Certificate renewal successful" -ForegroundColor Green
}
```

**Common Causes**:
- Certificate expired and not renewed
- Automated renewal process failed
- System clock skew (check with `w32tm /query /status`)

---

### 🔧 Workflow 2: Revocation Check Failures

**Symptoms**: Slow validation, timeouts, intermittent connection failures

**Diagnosis**:
```powershell
# Find revocation check issues
Find-CapiEventsByName -Name "*.contoso.com" -FilterType Revocation -Hours 24 |
    Get-CapiErrorAnalysis
```

**Resolution Steps**:
```powershell
# 1. Identify affected certificates
$RevErrors = Find-CapiEventsByName -Name "*.contoso.com" -FilterType Revocation
$Analysis = Get-CapiErrorAnalysis -Events $RevErrors[0].Events

# 2. Test CRL/OCSP endpoint connectivity
$Cert = Get-Item Cert:\LocalMachine\My\<Thumbprint>
$CRLUrls = $Cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "CRL Distribution Points" }

# Test HTTP connectivity to CRL URLs
$CRLUrls | ForEach-Object {
    $Url = $_.Format($false) -replace '.*URL=([^\s]+).*','$1'
    try {
        $Response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10
        Write-Host "✓ Reachable - $Url" -ForegroundColor Green
    } catch {
        Write-Host "✗ Unreachable - $Url" -ForegroundColor Red
    }
}

# 3. Check firewall/proxy settings
# - Verify outbound HTTP (80) and HTTPS (443) allowed
# - Check proxy: netsh winhttp show proxy
# - Test with: certutil -url <CertificateFile>

# 4. Verify fix
Start-Sleep -Seconds 60
$AfterFix = Find-CapiEventsByName -Name "*.contoso.com" -FilterType Revocation -Hours 1
if (-not $AfterFix) {
    Write-Host "✓ Revocation checks now successful" -ForegroundColor Green
}
```

**Common Causes**:
- CRL/OCSP URL unreachable (firewall/proxy)
- OCSP responder server down
- DNS resolution failures
- HTTP proxy not configured (`netsh winhttp set proxy`)

---

### 🔧 Workflow 3: Untrusted Root Certificate

**Symptoms**: "Certificate chain issued by untrusted authority" errors

**Diagnosis**:
```powershell
# Find untrusted root issues
Find-CapiEventsByName -Name "*.internal.local" -FilterType Untrusted -Hours 24 |
    Get-CapiErrorAnalysis
```

**Resolution Steps**:
```powershell
# 1. Identify untrusted certificates
$Untrusted = Find-CapiEventsByName -Name "*" -FilterType Untrusted -Hours 24
$Analysis = Get-CapiErrorAnalysis -Events $Untrusted[0].Events
$Analysis | Format-Table Certificate, Issuer, Thumbprint -AutoSize

# 2. Export root CA certificate from issuing server
# On CA server:
certutil -ca.cert C:\RootCA.cer

# 3. Install root CA on affected machine
Import-Certificate -FilePath "C:\RootCA.cer" -CertStoreLocation Cert:\LocalMachine\Root

# Or via certutil:
certutil -addstore -enterprise -f Root C:\RootCA.cer

# 4. Deploy via Group Policy (recommended for enterprise)
# Computer Configuration → Windows Settings → Security Settings → 
# Public Key Policies → Trusted Root Certification Authorities → Import

# 5. Verify certificate installed
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*Internal Root CA*" }

# 6. Verify fix
Start-Sleep -Seconds 60
$AfterFix = Find-CapiEventsByName -Name "*.internal.local" -FilterType Untrusted -Hours 1
if (-not $AfterFix) {
    Write-Host "✓ Root CA now trusted" -ForegroundColor Green
}
```

**Common Causes**:
- Internal/private CA certificate not installed
- Self-signed certificates not explicitly trusted
- Root CA certificate expired or removed

---

### 🔧 Workflow 4: Certificate Chain Building Failures

**Symptoms**: "Cannot build chain to trusted root authority"

**Diagnosis**:
```powershell
# Find chain building errors
Find-CapiEventsByName -Name "*.contoso.com" -FilterType ChainBuilding -Hours 24 |
    Get-CapiErrorAnalysis
```

**Resolution Steps**:
```powershell
# 1. Identify missing intermediate certificates
$ChainErrors = Find-CapiEventsByName -Name "*.contoso.com" -FilterType ChainBuilding
$Analysis = Get-CapiErrorAnalysis -Events $ChainErrors[0].Events
$Analysis | Where-Object { $_.ErrorName -eq 'CERT_E_CHAINING' } | ForEach-Object {
    Write-Host "End Certificate: $($_.Certificate)" -ForegroundColor Yellow
    Write-Host "Missing Issuer: $($_.Issuer)" -ForegroundColor Red
}

# 2. Check Authority Information Access (AIA) extension
$Cert = Get-Item Cert:\LocalMachine\My\<Thumbprint>
$AIAExt = $Cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Authority Information Access" }
$AIAExt.Format($false)

# Output shows CA Issuers URL:
# URL=http://pki.contoso.com/certs/ContosoIssuingCA01.crt

# 3. Download intermediate certificate
$IntermediateUrl = "http://pki.contoso.com/certs/ContosoIssuingCA01.crt"
Invoke-WebRequest -Uri $IntermediateUrl -OutFile "C:\Temp\Intermediate.crt"

# 4. Install intermediate certificate
Import-Certificate -FilePath "C:\Temp\Intermediate.crt" -CertStoreLocation Cert:\LocalMachine\CA

# Or via certutil:
certutil -addstore -enterprise CA C:\Temp\Intermediate.crt

# 5. Verify intermediate installed
Get-ChildItem Cert:\LocalMachine\CA | Where-Object { $_.Subject -like "*Contoso Issuing CA*" }

# 6. Test certificate chain building
certutil -verify -urlfetch Cert:\LocalMachine\My\<Thumbprint>

# 7. Verify fix
Start-Sleep -Seconds 60
$AfterFix = Find-CapiEventsByName -Name "*.contoso.com" -FilterType ChainBuilding -Hours 1
if (-not $AfterFix) {
    Write-Host "✓ Certificate chain now builds successfully" -ForegroundColor Green
}
```

**Common Causes**:
- Intermediate certificate not included in server configuration
- AIA extension missing or pointing to unreachable URL
- Intermediate certificate not installed in CA store

---

### 🔧 Workflow 5: Certificate Name Mismatch (CN_NO_MATCH)

**Symptoms**: "Certificate CN name doesn't match passed value"

**Diagnosis**:
```powershell
# Find CN mismatch errors
Find-CapiEventsByName -Name "*.contoso.com" -Hours 24 | ForEach-Object {
    $Analysis = Get-CapiErrorAnalysis -Events $_.Events
    $Analysis | Where-Object { $_.ErrorName -eq 'CERT_E_CN_NO_MATCH' }
}
```

**Resolution Steps**:
```powershell
# 1. Identify certificate and requested hostname
$Results = Find-CapiEventsByName -Name "new.contoso.com" -Hours 24
$Analysis = Get-CapiErrorAnalysis -Events $Results[0].Events
$CNErrors = $Analysis | Where-Object { $_.ErrorName -eq 'CERT_E_CN_NO_MATCH' }
$CNErrors | Format-Table Certificate, Thumbprint, Description -Wrap

# 2. Check Subject Alternative Names (SANs)
$Cert = Get-Item Cert:\LocalMachine\My\<Thumbprint>
$SANExt = $Cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
$SANExt.Format($false)

# 3. Resolution options:

# Option A: Request new certificate with correct CN/SAN
# - Include all hostnames needed (CN and SANs)
# - Use wildcard certificate: *.contoso.com

# Option B: Add DNS CNAME record (if acceptable)
# Add DNS CNAME: new.contoso.com → old.contoso.com

# Option C: Update application to use correct hostname

# 4. Request new certificate with SANs (example)
$CertRequest = @"
[NewRequest]
Subject = "CN=new.contoso.com, O=Contoso, C=US"
KeyLength = 2048

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=new.contoso.com&"
_continue_ = "dns=www.new.contoso.com"
"@

$CertRequest | Out-File C:\Temp\request.inf
certreq -new C:\Temp\request.inf C:\Temp\request.req

# 5. Verify fix
Start-Sleep -Seconds 60
$AfterFix = Find-CapiEventsByName -Name "new.contoso.com" -Hours 1 | ForEach-Object {
    Get-CapiErrorAnalysis -Events $_.Events | Where-Object { $_.ErrorName -eq 'CERT_E_CN_NO_MATCH' }
}
if (-not $AfterFix) {
    Write-Host "✓ Certificate name now matches" -ForegroundColor Green
}
```

**Common Causes**:
- Certificate CN doesn't match requested hostname
- Missing Subject Alternative Name (SAN) entries
- Accessing site by IP address when certificate has hostnames only

---

### 🔧 Workflow 6: Policy Validation Failures

**Symptoms**: "Certificate not valid for requested usage"

**Diagnosis**:
```powershell
# Find policy/usage errors
Find-CapiEventsByName -Name "*" -FilterType Policy -Hours 24 |
    Get-CapiErrorAnalysis
```

**Resolution Steps**:
```powershell
# 1. Identify policy errors
$PolicyErrors = Find-CapiEventsByName -Name "*" -FilterType Policy -Hours 24
$Analysis = Get-CapiErrorAnalysis -Events $PolicyErrors[0].Events
$Analysis | Format-Table ErrorName, Certificate, Description, Resolution -Wrap

# 2. Check Enhanced Key Usage (EKU) extensions
$Cert = Get-Item Cert:\LocalMachine\My\<Thumbprint>
$EKUExt = $Cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Enhanced Key Usage" }
$EKUExt.Format($false)

# 3. Check certificate basic constraints
$BCExt = $Cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Basic Constraints" }
$BCExt.Format($false)

# 4. Resolution: Request certificate with correct EKU

# For web servers (IIS/Apache/Nginx):
# - EKU: Server Authentication (1.3.6.1.5.5.7.3.1)

# For client certificates:
# - EKU: Client Authentication (1.3.6.1.5.5.7.3.2)

# For email (S/MIME):
# - EKU: Secure Email (1.3.6.1.5.5.7.3.4)

# For code signing:
# - EKU: Code Signing (1.3.6.1.5.5.7.3.3)

# 5. Request new certificate using appropriate template

# 6. Verify fix
Start-Sleep -Seconds 60
$AfterFix = Find-CapiEventsByName -Name "*" -FilterType Policy -Hours 1
if (-not $AfterFix) {
    Write-Host "✓ Certificate policy validation successful" -ForegroundColor Green
}
```

**Common Causes**:
- Wrong certificate template used during enrollment
- Certificate enrolled for wrong purpose (client cert used for server)
- CA certificate used as end-entity certificate
- Custom EKU OIDs not recognized

---

### 📊 Advanced: Automated Monitoring

Create proactive certificate monitoring with scheduled tasks:

```powershell
# Save as C:\Scripts\Monitor-Certificates.ps1
param(
    [string[]]$Domains = @("*.contoso.com", "*.api.contoso.com"),
    [int]$Hours = 2,
    [string]$ReportPath = "C:\CertMonitoring\Reports",
    [string]$AlertEmail = "it-security@contoso.com"
)

$Alerts = @()

# Check for critical issues
foreach ($Domain in $Domains) {
    # Expired certificates (CRITICAL)
    $Expired = Find-CapiEventsByName -Name $Domain -FilterType Expired -Hours $Hours
    if ($Expired) {
        $Analysis = Get-CapiErrorAnalysis -Events $Expired[0].Events
        $Alerts += $Analysis | ForEach-Object {
            [PSCustomObject]@{
                Timestamp = Get-Date
                Severity = "CRITICAL"
                Type = "Expired Certificate"
                Domain = $Domain
                Certificate = $_.Certificate
                ErrorCode = $_.ErrorCode
            }
        }
    }
    
    # Untrusted roots (CRITICAL)
    $Untrusted = Find-CapiEventsByName -Name $Domain -FilterType Untrusted -Hours $Hours
    if ($Untrusted) {
        $Analysis = Get-CapiErrorAnalysis -Events $Untrusted[0].Events
        $Alerts += $Analysis | ForEach-Object {
            [PSCustomObject]@{
                Timestamp = Get-Date
                Severity = "CRITICAL"
                Type = "Untrusted Root"
                Domain = $Domain
                Certificate = $_.Certificate
                ErrorCode = $_.ErrorCode
            }
        }
    }
    
    # Revocation failures (WARNING)
    $Revocation = Find-CapiEventsByName -Name $Domain -FilterType Revocation -Hours $Hours
    if ($Revocation) {
        $Analysis = Get-CapiErrorAnalysis -Events $Revocation[0].Events
        $Alerts += $Analysis | ForEach-Object {
            [PSCustomObject]@{
                Timestamp = Get-Date
                Severity = "WARNING"
                Type = "Revocation Check Failed"
                Domain = $Domain
                Certificate = $_.Certificate
                ErrorCode = $_.ErrorCode
            }
        }
    }
}

# Generate alert if issues found
if ($Alerts.Count -gt 0) {
    $Alerts | Format-Table Timestamp, Severity, Type, Certificate -AutoSize
    
    $ReportFile = Join-Path $ReportPath "CertAlert_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $Alerts | ConvertTo-Html -Title "Certificate Alert Report" | Out-File $ReportFile
    
    $CriticalCount = ($Alerts | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    if ($CriticalCount -gt 0) {
        Write-Host "[ALERT] $CriticalCount critical certificate issues!" -ForegroundColor Red
        # Send-MailMessage -To $AlertEmail -From "certmonitor@contoso.com" ...
    }
} else {
    Write-Host "[OK] No certificate issues detected" -ForegroundColor Green
}
```

**Schedule the monitoring script**:
```powershell
# Create scheduled task (runs hourly)
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Scripts\Monitor-Certificates.ps1"

$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)

$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "CAPI2-Certificate-Monitor" `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Description "Monitors certificate validation errors via CAPI2"
```

---

### 📊 Advanced: Bulk Processing

Process multiple domains and generate consolidated reports:

```powershell
$Domains = @("*.contoso.com", "*.api.contoso.com", "*.internal.local")
$AllErrors = @()

foreach ($Domain in $Domains) {
    Write-Host "`n=== Processing: $Domain ===" -ForegroundColor Cyan
    
    $Results = Find-CapiEventsByName -Name $Domain -Hours 24
    
    foreach ($Result in $Results) {
        $Errors = Get-CapiErrorAnalysis -Events $Result.Events
        
        if ($Errors) {
            $Errors | ForEach-Object {
                $_ | Add-Member -NotePropertyName "Domain" -NotePropertyValue $Domain -Force
                $_ | Add-Member -NotePropertyName "TaskID" -NotePropertyValue $Result.TaskID -Force
            }
            
            $AllErrors += $Errors
            
            # Export individual chain report
            Export-CapiEvents -Events $Result.Events `
                              -Path "C:\Reports" `
                              -Format HTML `
                              -IncludeErrorAnalysis `
                              -TaskID $Result.TaskID
        }
    }
}

# Generate consolidated CSV report
$AllErrors | Export-Csv -Path "C:\Reports\Consolidated_Errors.csv" -NoTypeInformation

# Display summary
Write-Host "`n=== Bulk Analysis Summary ===" -ForegroundColor Green
Write-Host "Total Domains: $($Domains.Count)"
Write-Host "Total Errors: $($AllErrors.Count)"

# Error distribution
$AllErrors | Group-Object ErrorName | 
    Sort-Object Count -Descending |
    Format-Table Count, Name -AutoSize
```

---

### 🛠️ CAPI2 Event Log Management

Control CAPI2 event logging:

```powershell
# Check status
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
```

---

### 📁 Export Formats

#### HTML (Recommended)
```powershell
Export-CapiEvents -Events $Events -Path "C:\Reports\report.html" -Format HTML -IncludeErrorAnalysis
```
- Color-coded error severity
- Complete error descriptions
- Step-by-step resolution instructions
- Event timeline tables
- Certificate details with SANs

#### JSON (For Automation)
```powershell
Export-CapiEvents -Events $Events -Path "C:\Reports\data.json" -Format JSON
```
- Integration with monitoring systems
- Automated processing with PowerShell
- Data analysis and reporting

#### CSV (For Spreadsheets)
```powershell
Export-CapiEvents -Events $Events -Path "C:\Reports\data.csv" -Format CSV
```
- Excel analysis
- Bulk data processing
- Sharing with non-technical teams

#### XML (For SIEM/Integration)
```powershell
Export-CapiEvents -Events $Events -Path "C:\Reports\data.xml" -Format XML
```
- SIEM system ingestion
- Enterprise log management
- Structured data interchange

---

### 🔎 View Complete Event Chain (v2.11+)

See all events in the correlation chain with X.509 certificate information:

```powershell
# Display with full event chain
$Results = Find-CapiEventsByName -Name "*.events.data.microsoft.com"
Get-CapiErrorAnalysis -Events $Results[0].Events -ShowEventChain
```

**Sample Output:**
```
╔═══════════════════════════════════════════════════════════════╗
║           Certificate Information (Event 90)                  ║
╚═══════════════════════════════════════════════════════════════╝
  Subject CN:      *.events.data.microsoft.com
  Organization:    Microsoft Corporation
  Country:         US
  Issued By:       Microsoft Azure RSA TLS Issuing CA 07
  SANs:            DNS: *.events.data.microsoft.com
                   DNS: events.data.microsoft.com
                   DNS: *.pipe.aria.microsoft.com
                   DNS: pipe.skype.com
  Serial:          0A1B2C3D4E5F60718293A4B5C6D7E8F9
  Valid:           2024-11-15 to 2025-05-14

=== CAPI2 Correlation Chain Events ===
Sequence TimeCreated          Level       EventID TaskCategory
-------- -----------          -----       ------- ------------
1        10/12/2025 21:05:07  Information 11      Build Chain
2        10/12/2025 21:05:07  Information 90      X509 Objects
3        10/12/2025 21:05:07  Information 30      Verify Chain Policy
```

---

## 🔐 Error Codes Reference
