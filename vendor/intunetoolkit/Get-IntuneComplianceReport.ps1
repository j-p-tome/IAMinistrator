#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Generates a comprehensive compliance report for Intune-managed devices.
.DESCRIPTION
    Exports device compliance states with per-policy breakdown, identifies
    non-compliant devices, and summarizes compliance by OS and policy.
.PARAMETER ExportPath
    Optional. Export to CSV.
.PARAMETER IncludeCompliant
    Include compliant devices in the export (default: all devices).

Attribution: IntuneToolKit by AliAlame
  https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit
#>

[CmdletBinding()]
param(
    [Parameter()][string]$ExportPath,
    [Parameter()][switch]$IncludeCompliant
)

function Write-Status { param([string]$Msg,[string]$Color='Cyan'); Write-Host "  [$((Get-Date).ToString('HH:mm:ss'))] $Msg" -ForegroundColor $Color }
function Write-Section { param([string]$Msg); Write-Host "`n$('='*60)" -ForegroundColor DarkGray; Write-Host "  $Msg" -ForegroundColor Yellow; Write-Host "$('='*60)" -ForegroundColor DarkGray }

function Invoke-MgGraph-Safe {
    param([string]$Uri,[string]$Method='GET')
    try {
        $response = Invoke-MgGraphRequest -Uri $Uri -Method $Method -ErrorAction Stop
        $results = @()
        if ($null -ne $response.value) { $results += $response.value } elseif ($response) { $results += $response }
        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET -ErrorAction Stop
            if ($null -ne $response.value) { $results += $response.value }
        }
        return ,$results
    } catch { Write-Verbose "Graph call failed: $_"; return @() }
}

Write-Section "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "LOADING DEVICES"
$devices = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,lastSyncDateTime,enrolledDateTime,managementAgent,deviceType'
Write-Status "$($devices.Count) managed devices" "Green"

Write-Section "LOADING COMPLIANCE POLICIES"
$policies = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$select=id,displayName,@odata.type&$expand=assignments'
Write-Status "$($policies.Count) compliance policies" "Green"

Write-Section "BUILDING DEVICE COMPLIANCE REPORT"
$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$now = Get-Date; $staleThreshold = 7

$i = 0
foreach ($device in $devices) {
    $i++
    if ($i % 100 -eq 0) { Write-Progress -Activity "Processing devices" -Status "$i / $($devices.Count)" -PercentComplete (($i/$devices.Count)*100) }

    # Per-device compliance details
    $deviceStatuses = @()
    try {
        $statusResult = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($device.id)/deviceCompliancePolicyStates?`$select=displayName,state,settingCount,errorCount" -Method GET -ErrorAction Stop
        if ($statusResult.value) { $deviceStatuses = $statusResult.value }
    } catch { }

    $lastSync = if ($device.lastSyncDateTime) { [datetime]$device.lastSyncDateTime } else { $null }
    $daysSinceSync = if ($lastSync) { ($now - $lastSync).Days } else { 9999 }

    $nonCompliantPolicies = ($deviceStatuses | Where-Object { $_.state -in @('nonCompliant','error','conflict') }) | ForEach-Object { $_.displayName }
    $compliantPolicies = ($deviceStatuses | Where-Object { $_.state -eq 'compliant' }) | ForEach-Object { $_.displayName }

    $issues = @()
    if ($device.complianceState -eq 'noncompliant') { $issues += 'NonCompliant' }
    if ($daysSinceSync -gt $staleThreshold) { $issues += "Stale ($daysSinceSync d)" }

    if ($device.complianceState -ne 'compliant' -or $IncludeCompliant) {
        $report.Add([PSCustomObject]@{
            DeviceName           = $device.deviceName
            UPN                  = $device.userPrincipalName
            OS                   = $device.operatingSystem
            OSVersion            = $device.osVersion
            ComplianceState      = $device.complianceState
            LastSync             = $lastSync
            DaysSinceSync        = $daysSinceSync
            PolicyCount          = $deviceStatuses.Count
            CompliantPolicies    = $compliantPolicies -join '; '
            NonCompliantPolicies = $nonCompliantPolicies -join '; '
            Issues               = if ($issues.Count -gt 0) { $issues -join '; ' } else { '-' }
        })
    }
}
Write-Progress -Activity "Processing devices" -Completed

$totalDevices = $devices.Count
$compliant = ($devices | Where-Object { $_.complianceState -eq 'compliant' }).Count
$nonCompliant = ($devices | Where-Object { $_.complianceState -eq 'noncompliant' }).Count
$unknown = ($devices | Where-Object { $_.complianceState -in @('unknown','configManager','inGracePeriod') }).Count
$staleCount = ($devices | Where-Object { $_.lastSyncDateTime -and (($now - [datetime]$_.lastSyncDateTime).Days -gt $staleThreshold) }).Count

Write-Section "SUMMARY"
Write-Host "  Total devices    : $totalDevices" -ForegroundColor White
Write-Host "  Compliant        : $compliant  ($([math]::Round($compliant/$totalDevices*100,1))%)" -ForegroundColor Green
Write-Host "  Non-Compliant    : $nonCompliant  ($([math]::Round($nonCompliant/$totalDevices*100,1))%)" -ForegroundColor $(if($nonCompliant -gt 0){'Red'}else{'Green'})
Write-Host "  Unknown/Grace    : $unknown" -ForegroundColor DarkGray
Write-Host "  Stale (>$staleThreshold d)    : $staleCount" -ForegroundColor $(if($staleCount -gt 0){'Yellow'}else{'Green'})

# OS breakdown
$osBreakdown = $devices | Group-Object operatingSystem | Sort-Object Count -Descending
Write-Host ""
Write-Host "  OS Breakdown:" -ForegroundColor White
foreach ($os in $osBreakdown) {
    $osNc = ($devices | Where-Object { $_.operatingSystem -eq $os.Name -and $_.complianceState -eq 'noncompliant' }).Count
    Write-Host "    $($os.Name): $($os.Count) total, $osNc non-compliant" -ForegroundColor DarkGray
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "ComplianceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($report.Count) rows)" "Green"
Write-Host ""
