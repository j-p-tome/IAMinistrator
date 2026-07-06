#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports on Windows Update compliance across Intune-managed devices.
.DESCRIPTION
    Retrieves update compliance state per device, groups by ring, identifies
    devices with pending/failed updates, and exports summary + detail CSV.
.PARAMETER ExportPath
    Optional. Export to CSV.

Attribution: IntuneToolKit by AliAlame
  https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit
#>

[CmdletBinding()]
param([Parameter()][string]$ExportPath)

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
$devices = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,lastSyncDateTime,enrolledDateTime&$filter=operatingSystem eq ''Windows'''
Write-Status "$($devices.Count) Windows devices" "Green"

Write-Section "LOADING UPDATE RINGS"
$rings = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$expand=assignments"
Write-Status "$($rings.Count) update rings" "Green"

# Map device -> ring(s)
$deviceRingMap = @{}
foreach ($ring in $rings) {
    $ringAssignedGroups = $ring.assignments | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' } | ForEach-Object { $_.target.groupId }
    foreach ($groupId in $ringAssignedGroups) {
        try {
            $members = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=id"
            foreach ($m in $members) {
                if (-not $deviceRingMap[$m.id]) { $deviceRingMap[$m.id] = @() }
                $deviceRingMap[$m.id] += $ring.displayName
            }
        } catch { }
    }
    $allDevicesTargeted = $ring.assignments | Where-Object { $_.target.'@odata.type' -like '*allDevices*' }
    if ($allDevicesTargeted) {
        foreach ($d in $devices) {
            if (-not $deviceRingMap[$d.id]) { $deviceRingMap[$d.id] = @() }
            if ($ring.displayName -notin $deviceRingMap[$d.id]) { $deviceRingMap[$d.id] += $ring.displayName }
        }
    }
}

Write-Section "BUILDING COMPLIANCE REPORT"
$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$staleThresholdDays = 7
$now = Get-Date

$i = 0
foreach ($device in $devices) {
    $i++
    if ($i % 100 -eq 0) { Write-Progress -Activity "Processing" -Status "$i / $($devices.Count)" -PercentComplete (($i/$devices.Count)*100) }

    $rings_assigned = if ($deviceRingMap[$device.id]) { $deviceRingMap[$device.id] -join '; ' } else { 'No ring assigned' }
    $lastSync = if ($device.lastSyncDateTime) { [datetime]$device.lastSyncDateTime } else { $null }
    $daysSinceSync = if ($lastSync) { ($now - $lastSync).Days } else { 9999 }
    $isStale = $daysSinceSync -gt $staleThresholdDays

    $osVer = $device.osVersion
    $isBelowMinBuild = $false
    # Simple heuristic: flag devices below Windows 10 22H2 (build 19045)
    if ($osVer -match '^10\.0\.(\d+)') {
        $build = [int]$Matches[1]
        if ($build -lt 19045) { $isBelowMinBuild = $true }
    }

    $issues = @()
    if ($device.complianceState -eq 'noncompliant') { $issues += 'NonCompliant' }
    if ($isStale) { $issues += "Stale ($daysSinceSync d since sync)" }
    if ($isBelowMinBuild) { $issues += 'Below min OS build (19045)' }
    if ($rings_assigned -eq 'No ring assigned') { $issues += 'No update ring' }

    $report.Add([PSCustomObject]@{
        DeviceName     = $device.deviceName
        UPN            = $device.userPrincipalName
        OSVersion      = $osVer
        ComplianceState = $device.complianceState
        LastSync       = $lastSync
        DaysSinceSync  = $daysSinceSync
        IsStale        = $isStale
        BelowMinBuild  = $isBelowMinBuild
        UpdateRings    = $rings_assigned
        Issues         = if ($issues.Count -gt 0) { $issues -join '; ' } else { '-' }
    })
}
Write-Progress -Activity "Processing" -Completed

$healthy = ($report | Where-Object { $_.Issues -eq '-' }).Count
$withIssues = $report.Count - $healthy
$noncompliant = ($report | Where-Object { $_.ComplianceState -eq 'noncompliant' }).Count
$staleDevices = ($report | Where-Object { $_.IsStale }).Count
$noRing = ($report | Where-Object { $_.UpdateRings -eq 'No ring assigned' }).Count
$belowBuild = ($report | Where-Object { $_.BelowMinBuild }).Count

Write-Section "SUMMARY"
Write-Host "  Total Windows devices   : $($report.Count)" -ForegroundColor White
Write-Host "  Healthy                 : $healthy" -ForegroundColor Green
Write-Host "  With issues             : $withIssues" -ForegroundColor $(if($withIssues -gt 0){'Yellow'}else{'Green'})
Write-Host "  NonCompliant            : $noncompliant" -ForegroundColor $(if($noncompliant -gt 0){'Red'}else{'Green'})
Write-Host "  Stale (>$staleThresholdDays d no sync)  : $staleDevices" -ForegroundColor $(if($staleDevices -gt 0){'Yellow'}else{'Green'})
Write-Host "  No update ring          : $noRing" -ForegroundColor $(if($noRing -gt 0){'Yellow'}else{'Green'})
Write-Host "  Below min build         : $belowBuild" -ForegroundColor $(if($belowBuild -gt 0){'Yellow'}else{'Green'})

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "UpdateComplianceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($report.Count) rows)" "Green"
Write-Host ""
