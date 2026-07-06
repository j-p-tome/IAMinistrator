#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Audits Windows Update ring configurations against Microsoft best practices.
.DESCRIPTION
    Checks every update ring against Microsoft's Autopatch-recommended values
    and common misconfiguration patterns.

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
        if ($null -ne $response.value) { $results += $response.value }
        elseif ($response) { $results += $response }
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
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "LOADING UPDATE ENVIRONMENT"
$rings = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$expand=assignments"
Write-Status "$($rings.Count) update rings" "Green"

$featureProfiles = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles"
$driverProfiles = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles"
Write-Status "$($featureProfiles.Count) feature update profiles, $($driverProfiles.Count) driver update profiles" "Green"

$bestPractice = @{ MaxQualityDeferral=14; MinQualityDeadline=2; MaxQualityDeadline=7; MinGracePeriod=2; MaxGracePeriod=5; MaxFeatureDeferral=0; RecommendedDO='httpWithPeeringNat' }

$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$totalFindings = 0

Write-Section "AUDIT FINDINGS"
Write-Host ""

foreach ($ring in ($rings | Sort-Object displayName)) {
    $name = $ring.displayName
    $findings = @()

    $assignCount = 0; $hasAllDevices = $false
    if ($ring.assignments) {
        $assignCount = ($ring.assignments | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' }).Count
        $hasAllDevices = ($ring.assignments | Where-Object { $_.target.'@odata.type' -like '*allDevices*' }).Count -gt 0
    }
    $totalAssignments = $assignCount + $(if ($hasAllDevices) { 1 } else { 0 })
    if ($totalAssignments -eq 0) { $findings += [PSCustomObject]@{ Severity='Medium'; Finding='No assignments - ring has no effect'; Category='Assignment' } }

    $qd = $ring.qualityUpdatesDeferralPeriodInDays
    if ($qd -gt $bestPractice.MaxQualityDeferral) { $findings += [PSCustomObject]@{ Severity='High'; Finding="Quality deferral $qd days exceeds recommended max ($($bestPractice.MaxQualityDeferral) days)"; Category='Deferral' } }
    if ($qd -eq 0 -and $totalAssignments -gt 1) { $findings += [PSCustomObject]@{ Severity='Medium'; Finding='Zero quality deferral with broad assignment - no buffer for bad patches'; Category='Deferral' } }

    $qdl = $ring.qualityUpdatesDeadlineInDays
    if (-not $qdl -or $qdl -eq 0) { $findings += [PSCustomObject]@{ Severity='High'; Finding='No quality update deadline - devices may never install updates'; Category='Deadline' } }
    if ($qdl -and $qdl -gt $bestPractice.MaxQualityDeadline) { $findings += [PSCustomObject]@{ Severity='Medium'; Finding="Quality deadline $qdl days exceeds recommended max ($($bestPractice.MaxQualityDeadline) days)"; Category='Deadline' } }

    $gp = $ring.qualityUpdatesGracePeriodInDays
    if (-not $gp -or $gp -eq 0) { $findings += [PSCustomObject]@{ Severity='Medium'; Finding='Zero grace period - devices forced to reboot immediately after deadline'; Category='Grace' } }

    if ($ring.qualityUpdatesPaused) { $findings += [PSCustomObject]@{ Severity='Critical'; Finding='Quality updates are PAUSED - devices are not receiving security patches'; Category='Pause' } }
    if ($ring.featureUpdatesPaused) { $findings += [PSCustomObject]@{ Severity='Medium'; Finding='Feature updates are PAUSED'; Category='Pause' } }

    $fd = $ring.featureUpdatesDeferralPeriodInDays
    if ($fd -gt 0 -and $featureProfiles.Count -gt 0) { $findings += [PSCustomObject]@{ Severity='High'; Finding="Feature deferral $fd days set while Feature Update profiles exist - may block feature updates"; Category='FeatureConflict' } }
    if ($fd -gt 365) { $findings += [PSCustomObject]@{ Severity='High'; Finding="Feature deferral $fd days - effectively blocking feature updates"; Category='Deferral' } }

    if ($ring.driversExcluded -and $driverProfiles.Count -gt 0) { $findings += [PSCustomObject]@{ Severity='High'; Finding='Drivers excluded while Driver Update profiles exist - profiles will be blocked'; Category='DriverConflict' } }

    $do = $ring.deliveryOptimizationMode
    if ($do -eq 'httpOnly') { $findings += [PSCustomObject]@{ Severity='Low'; Finding='Delivery Optimization set to HTTP only - no peer-to-peer bandwidth savings'; Category='DeliveryOpt' } }

    $fdl = $ring.featureUpdatesDeadlineInDays
    if (-not $fdl -or $fdl -eq 0) { $findings += [PSCustomObject]@{ Severity='Low'; Finding='No feature update deadline set'; Category='Deadline' } }

    if ($hasAllDevices) {
        $excludeCount = ($ring.assignments | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' }).Count
        if ($excludeCount -eq 0) { $findings += [PSCustomObject]@{ Severity='Medium'; Finding='Targets All Devices with NO exclusions - every device gets this ring'; Category='Assignment' } }
    }

    $color = if (($findings | Where-Object { $_.Severity -eq 'Critical' }).Count -gt 0) { 'Red' } elseif (($findings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) { 'Yellow' } elseif ($findings.Count -gt 0) { 'DarkYellow' } else { 'Green' }
    $statusTag = if ($findings.Count -eq 0) { '[HEALTHY]' } elseif (($findings | Where-Object { $_.Severity -eq 'Critical' }).Count -gt 0) { '[CRITICAL]' } elseif (($findings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) { '[ISSUES]' } else { '[REVIEW]' }
    Write-Host "  $statusTag $name" -ForegroundColor $color
    Write-Host "    Defer: Q=$qd d / F=$fd d | Deadline: Q=$qdl d / F=$fdl d | Grace: $gp d | DO: $do" -ForegroundColor DarkGray
    if ($findings.Count -gt 0) {
        foreach ($f in ($findings | Sort-Object { switch($_.Severity){'Critical'{0}'High'{1}'Medium'{2}default{3}} })) {
            $fColor = switch ($f.Severity) { 'Critical'{'Red'} 'High'{'Yellow'} 'Medium'{'DarkYellow'} default{'DarkGray'} }
            Write-Host "    [$($f.Severity.ToUpper())] $($f.Finding)" -ForegroundColor $fColor
        }
        $totalFindings += $findings.Count
    }
    Write-Host ""
    foreach ($f in $findings) { $report.Add([PSCustomObject]@{ RingName=$name; Severity=$f.Severity; Category=$f.Category; Finding=$f.Finding; QualityDeferral=$qd; FeatureDeferral=$fd; QualityDeadline=$qdl; GracePeriod=$gp; Paused="Q:$($ring.qualityUpdatesPaused) F:$($ring.featureUpdatesPaused)"; DriversExcluded=$ring.driversExcluded; AssignmentCount=$totalAssignments }) }
}

Write-Section "SUMMARY"
Write-Host "  Total rings:   $($rings.Count)" -ForegroundColor White
Write-Host "  Total findings: $totalFindings" -ForegroundColor $(if($totalFindings -gt 0){'Yellow'}else{'Green'})

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "UpdateRingHealth_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
