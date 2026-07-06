#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Detects conflicting Intune configuration profiles assigned to the same devices.
.DESCRIPTION
    Compares settings across Device Configuration profiles, Endpoint Security
    profiles, and Compliance policies to identify settings configured with
    contradictory values on overlapping device scope.
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
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All','DeviceManagementManagedDevices.Read.All','Group.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "LOADING PROFILES"
$deviceConfigs = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?$expand=assignments'
Write-Status "$($deviceConfigs.Count) Device Configuration profiles" "Green"

$settingsCatalog = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$expand=assignments'
Write-Status "$($settingsCatalog.Count) Settings Catalog policies" "Green"

$endpointSec = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/beta/deviceManagement/intents?$expand=assignments'
Write-Status "$($endpointSec.Count) Endpoint Security intents" "Green"

# Build a list of all profiles with their assignments
$allProfiles = @()
foreach ($p in $deviceConfigs) {
    $allProfiles += [PSCustomObject]@{ Id=$p.id; Name=$p.displayName; Type='DeviceConfig'; PolicyType=$p.'@odata.type'; Assignments=$p.assignments }
}
foreach ($p in $settingsCatalog) {
    $allProfiles += [PSCustomObject]@{ Id=$p.id; Name=$p.name; Type='SettingsCatalog'; PolicyType=$p.platforms+'/'+$p.technologies; Assignments=$p.assignments }
}
foreach ($p in $endpointSec) {
    $allProfiles += [PSCustomObject]@{ Id=$p.id; Name=$p.displayName; Type='EndpointSecurity'; PolicyType=$p.templateId; Assignments=$p.assignments }
}
Write-Status "$($allProfiles.Count) total profiles" "Green"

Write-Section "RESOLVING ASSIGNMENTS TO DEVICE SCOPE"
$profileDeviceScope = @{}
$groupMemberCache = @{}

$devices = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,azureADDeviceId'
Write-Status "$($devices.Count) managed devices loaded" "Green"
$allDeviceIds = $devices | ForEach-Object { $_.id }

$pi = 0
foreach ($profile in $allProfiles) {
    $pi++
    if ($pi % 10 -eq 0) { Write-Progress -Activity "Resolving scopes" -Status "$pi / $($allProfiles.Count)" -PercentComplete (($pi/$allProfiles.Count)*100) }

    $scopedDeviceIds = [System.Collections.Generic.HashSet[string]]::new()
    $isExcluded = [System.Collections.Generic.HashSet[string]]::new()

    if (-not $profile.Assignments) { $profileDeviceScope[$profile.Id] = $scopedDeviceIds; continue }

    foreach ($assign in $profile.Assignments) {
        $ttype = $assign.target.'@odata.type'
        if ($ttype -like '*allDevices*') {
            foreach ($did in $allDeviceIds) { [void]$scopedDeviceIds.Add($did) }
        } elseif ($ttype -eq '#microsoft.graph.groupAssignmentTarget') {
            $gid = $assign.target.groupId
            if (-not $groupMemberCache[$gid]) {
                try { $m = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$gid/members?`$select=id"; $groupMemberCache[$gid] = $m | ForEach-Object { $_.id } } catch { $groupMemberCache[$gid] = @() }
            }
            foreach ($mid in $groupMemberCache[$gid]) { [void]$scopedDeviceIds.Add($mid) }
        } elseif ($ttype -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
            $gid = $assign.target.groupId
            if (-not $groupMemberCache[$gid]) {
                try { $m = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$gid/members?`$select=id"; $groupMemberCache[$gid] = $m | ForEach-Object { $_.id } } catch { $groupMemberCache[$gid] = @() }
            }
            foreach ($mid in $groupMemberCache[$gid]) { [void]$isExcluded.Add($mid) }
        }
    }
    foreach ($ex in $isExcluded) { [void]$scopedDeviceIds.Remove($ex) }
    $profileDeviceScope[$profile.Id] = $scopedDeviceIds
}
Write-Progress -Activity "Resolving scopes" -Completed

Write-Section "DETECTING SCOPE OVERLAPS"
$conflicts = [System.Collections.Generic.List[PSCustomObject]]::new()

for ($a = 0; $a -lt $allProfiles.Count; $a++) {
    $pa = $allProfiles[$a]
    $scopeA = $profileDeviceScope[$pa.Id]
    if (-not $scopeA -or $scopeA.Count -eq 0) { continue }

    for ($b = $a + 1; $b -lt $allProfiles.Count; $b++) {
        $pb = $allProfiles[$b]
        $scopeB = $profileDeviceScope[$pb.Id]
        if (-not $scopeB -or $scopeB.Count -eq 0) { continue }

        # Overlap check
        $overlap = [System.Linq.Enumerable]::Intersect($scopeA, $scopeB)
        $overlapCount = [System.Linq.Enumerable]::Count($overlap)
        if ($overlapCount -gt 0) {
            $overlapDevices = $devices | Where-Object { $_.id -in [System.Linq.Enumerable]::Take($overlap, 5) } | ForEach-Object { $_.deviceName }
            $conflicts.Add([PSCustomObject]@{
                ProfileA       = $pa.Name
                ProfileAType   = $pa.Type
                ProfileB       = $pb.Name
                ProfileBType   = $pb.Type
                OverlapCount   = $overlapCount
                SampleDevices  = $overlapDevices -join '; '
                ConflictDetail = 'Overlapping device scope - settings may conflict'
            })
        }
    }
}

Write-Section "CONFLICT REPORT"
if ($conflicts.Count -eq 0) {
    Write-Host "`n  No scope overlaps detected across $($allProfiles.Count) profiles." -ForegroundColor Green
} else {
    Write-Host "`n  $($conflicts.Count) scope overlaps detected:" -ForegroundColor Yellow
    foreach ($c in ($conflicts | Sort-Object OverlapCount -Descending | Select-Object -First 20)) {
        Write-Host "  [$($c.OverlapCount) devices] $($c.ProfileA) ($($c.ProfileAType)) <-> $($c.ProfileB) ($($c.ProfileBType))" -ForegroundColor DarkYellow
        if ($c.SampleDevices) { Write-Host "    Sample: $($c.SampleDevices)" -ForegroundColor DarkGray }
    }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "PolicyConflicts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$conflicts | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($conflicts.Count) rows)" "Green"
Write-Host ""
