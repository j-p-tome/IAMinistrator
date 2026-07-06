#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Inventories all Intune Group Policy (Administrative Template) configurations.
.DESCRIPTION
    Retrieves all Windows administrative template profiles, their assignments,
    and configured settings. Identifies unassigned profiles and exports full detail.
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
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All','Group.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "LOADING GROUP POLICY CONFIGURATIONS"
$profiles = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?$expand=assignments'
Write-Status "$($profiles.Count) Group Policy configurations found" "Green"

$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$unassigned = 0; $totalSettings = 0

$i = 0
foreach ($profile in ($profiles | Sort-Object displayName)) {
    $i++
    if ($i % 20 -eq 0) { Write-Progress -Activity "Processing profiles" -Status "$i / $($profiles.Count)" -PercentComplete (($i/$profiles.Count)*100) }

    # Get definitions/settings for this profile
    $definitions = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($profile.id)/definitionValues?`$expand=definition"
    $settingCount = $definitions.Count
    $totalSettings += $settingCount

    # Assignments
    $assignCount = 0; $assignGroups = @()
    if ($profile.assignments) {
        $groupAssignments = $profile.assignments | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' }
        $assignCount = $groupAssignments.Count
        foreach ($ga in $groupAssignments) {
            try {
                $grp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$($ga.target.groupId)?`$select=displayName" -Method GET -ErrorAction Stop
                $assignGroups += $grp.displayName
            } catch { $assignGroups += $ga.target.groupId }
        }
        $hasAllDevices = ($profile.assignments | Where-Object { $_.target.'@odata.type' -like '*allDevices*' }).Count -gt 0
        if ($hasAllDevices) { $assignCount++; $assignGroups += 'All Devices' }
        $hasAllUsers = ($profile.assignments | Where-Object { $_.target.'@odata.type' -like '*allLicensedUsers*' }).Count -gt 0
        if ($hasAllUsers) { $assignCount++; $assignGroups += 'All Users' }
    }
    if ($assignCount -eq 0) { $unassigned++ }

    # Build per-setting detail
    $settingNames = ($definitions | ForEach-Object { $_.definition.displayName }) -join ' | '

    # Enabled vs Disabled counts
    $enabledCount = ($definitions | Where-Object { $_.enabled -eq $true }).Count
    $disabledCount = ($definitions | Where-Object { $_.enabled -eq $false }).Count

    $issues = @()
    if ($assignCount -eq 0) { $issues += 'Not assigned' }
    if ($settingCount -eq 0) { $issues += 'No settings configured' }

    Write-Host "  $($profile.displayName)" -ForegroundColor $(if($issues.Count -gt 0){'Yellow'}else{'Cyan'})
    Write-Host "    Settings: $settingCount (Enabled: $enabledCount / Disabled: $disabledCount) | Assignments: $assignCount" -ForegroundColor DarkGray
    if ($assignGroups.Count -gt 0) { Write-Host "    Groups: $($assignGroups -join ', ')" -ForegroundColor DarkGray }
    if ($issues.Count -gt 0) { Write-Host "    ISSUES: $($issues -join '; ')" -ForegroundColor Yellow }
    Write-Host ""

    $report.Add([PSCustomObject]@{
        ProfileName      = $profile.displayName
        ProfileId        = $profile.id
        Created          = $profile.createdDateTime
        LastModified     = $profile.lastModifiedDateTime
        SettingCount     = $settingCount
        EnabledSettings  = $enabledCount
        DisabledSettings = $disabledCount
        AssignmentCount  = $assignCount
        AssignedGroups   = $assignGroups -join '; '
        Issues           = if ($issues.Count -gt 0) { $issues -join '; ' } else { '-' }
        TopSettings      = if ($settingNames.Length -gt 500) { $settingNames.Substring(0,500) + '...' } else { $settingNames }
    })
}
Write-Progress -Activity "Processing profiles" -Completed

Write-Section "SUMMARY"
Write-Host "  Total GP configurations : $($profiles.Count)" -ForegroundColor White
Write-Host "  Total settings          : $totalSettings" -ForegroundColor White
Write-Host "  Unassigned profiles     : $unassigned" -ForegroundColor $(if($unassigned -gt 0){'Yellow'}else{'Green'})

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "IntuneGroupPolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($report.Count) rows)" "Green"
Write-Host ""
