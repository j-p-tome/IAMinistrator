#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Generates a single-page HTML dashboard aggregating key Intune and Entra ID health metrics.
.DESCRIPTION
    Queries Microsoft Graph to gather device compliance, enrollment health,
    update ring status, app deployment stats, and policy conflict indicators,
    then renders them into a self-contained HTML dashboard file.
.PARAMETER OutputPath
    Path for the HTML output file. Default: IntuneDashboard.html in current dir.

Attribution: IntuneToolKit by AliAlame
  https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit
#>

[CmdletBinding()]
param(
    [Parameter()][string]$OutputPath = "IntuneDashboard.html"
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
    Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All','DeviceManagementApps.Read.All','Application.Read.All','Group.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "COLLECTING METRICS"

# 1. Device compliance
$devices = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,operatingSystem,complianceState,lastSyncDateTime'
Write-Status "$($devices.Count) managed devices" "Green"

$compliant    = ($devices | Where-Object { $_.complianceState -eq 'compliant'    }).Count
$nonCompliant = ($devices | Where-Object { $_.complianceState -eq 'noncompliant' }).Count
$unknown      = ($devices | Where-Object { $_.complianceState -notin @('compliant','noncompliant') }).Count

$now = Get-Date
$staleCount = ($devices | Where-Object { $_.lastSyncDateTime -and (($now - [datetime]$_.lastSyncDateTime).Days -gt 7) }).Count

$osCounts = $devices | Group-Object operatingSystem | Sort-Object Count -Descending
$osLabels  = ($osCounts | ForEach-Object { "'$($_.Name)'" }) -join ','
$osValues  = ($osCounts | ForEach-Object { $_.Count }) -join ','

# 2. Update rings
$rings = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')"
$pausedRings = ($rings | Where-Object { $_.qualityUpdatesPaused -or $_.featureUpdatesPaused }).Count
Write-Status "$($rings.Count) update rings ($pausedRings paused)" "Green"

# 3. Compliance policies
$compliancePolicies = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$select=id,displayName&$expand=assignments'
$unassignedPolicies = ($compliancePolicies | Where-Object { -not $_.assignments -or $_.assignments.Count -eq 0 }).Count
Write-Status "$($compliancePolicies.Count) compliance policies ($unassignedPolicies unassigned)" "Green"

# 4. Apps
$apps = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps?$select=id,displayName,publishingState&$filter=publishingState eq ''published'''
Write-Status "$($apps.Count) published apps" "Green"

# 5. App registrations expiring soon
$appRegs = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/v1.0/applications?$select=displayName,passwordCredentials,keyCredentials'
$expiringSoon = 0; $expiredCreds = 0
$warnDate = $now.AddDays(30)
foreach ($a in $appRegs) {
    $creds = @()
    if ($a.passwordCredentials) { $creds += $a.passwordCredentials }
    if ($a.keyCredentials) { $creds += $a.keyCredentials }
    foreach ($c in $creds) {
        if ($c.endDateTime) {
            $ed = [datetime]$c.endDateTime
            if ($ed -lt $now) { $expiredCreds++ } elseif ($ed -lt $warnDate) { $expiringSoon++ }
        }
    }
}
Write-Status "$($appRegs.Count) app registrations ($expiredCreds expired creds, $expiringSoon expiring soon)" "Green"

# 6. Enrollment failures (last 24h)
$since = (Get-Date).AddHours(-24).ToString('o')
$enrollFails = @()
try {
    $enrollFails = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/auditEvents?`$filter=activityType eq 'Enroll' and activityResult eq 'Fail' and activityDateTime ge $since&`$select=id"
} catch { }
Write-Status "$($enrollFails.Count) enrollment failures in last 24h" "Green"

Write-Section "RENDERING DASHBOARD"

$compliancePct = if ($devices.Count -gt 0) { [math]::Round($compliant/$devices.Count*100,1) } else { 0 }
$generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
$account = $context.Account

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Intune Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
  header{background:#1a1d27;border-bottom:1px solid #2d3148;padding:1rem 2rem;display:flex;align-items:center;justify-content:space-between}
  header h1{font-size:1.25rem;font-weight:600;color:#fff}header span{font-size:.8rem;color:#64748b}
  main{padding:2rem;max-width:1400px;margin:0 auto}
  .kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:1rem;margin-bottom:2rem}
  .kpi{background:#1a1d27;border:1px solid #2d3148;border-radius:.75rem;padding:1.25rem}
  .kpi-label{font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem}
  .kpi-value{font-size:2rem;font-weight:700;line-height:1}
  .kpi-sub{font-size:.75rem;color:#64748b;margin-top:.35rem}
  .green{color:#4ade80}.yellow{color:#facc15}.red{color:#f87171}.blue{color:#60a5fa}.purple{color:#a78bfa}
  .charts-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(400px,1fr));gap:1.5rem;margin-bottom:2rem}
  .chart-card{background:#1a1d27;border:1px solid #2d3148;border-radius:.75rem;padding:1.5rem}
  .chart-card h2{font-size:.875rem;font-weight:600;color:#94a3b8;margin-bottom:1rem;text-transform:uppercase;letter-spacing:.05em}
  .alerts{background:#1a1d27;border:1px solid #2d3148;border-radius:.75rem;padding:1.5rem;margin-bottom:2rem}
  .alerts h2{font-size:.875rem;font-weight:600;color:#94a3b8;margin-bottom:1rem;text-transform:uppercase;letter-spacing:.05em}
  .alert-item{display:flex;align-items:flex-start;gap:.75rem;padding:.75rem 0;border-bottom:1px solid #1e2233}
  .alert-item:last-child{border-bottom:none}
  .badge{display:inline-block;padding:.2rem .6rem;border-radius:999px;font-size:.7rem;font-weight:600;text-transform:uppercase}
  .badge-red{background:#7f1d1d;color:#fca5a5}.badge-yellow{background:#78350f;color:#fde68a}.badge-blue{background:#1e3a5f;color:#93c5fd}
  footer{text-align:center;padding:2rem;color:#334155;font-size:.75rem}
</style>
</head>
<body>
<header>
  <h1>&#x1F4F1; Intune Health Dashboard</h1>
  <span>Generated: $generatedAt &nbsp;|&nbsp; $account</span>
</header>
<main>

<div class="kpi-grid">
  <div class="kpi"><div class="kpi-label">Total Devices</div><div class="kpi-value blue">$($devices.Count)</div><div class="kpi-sub">Managed by Intune</div></div>
  <div class="kpi"><div class="kpi-label">Compliant</div><div class="kpi-value green">$compliant</div><div class="kpi-sub">$compliancePct% of fleet</div></div>
  <div class="kpi"><div class="kpi-label">Non-Compliant</div><div class="kpi-value $(if($nonCompliant -gt 0){'red'}else{'green'})">$nonCompliant</div><div class="kpi-sub">Require remediation</div></div>
  <div class="kpi"><div class="kpi-label">Stale (&gt;7d)</div><div class="kpi-value $(if($staleCount -gt 0){'yellow'}else{'green'})">$staleCount</div><div class="kpi-sub">No recent sync</div></div>
  <div class="kpi"><div class="kpi-label">Update Rings</div><div class="kpi-value blue">$($rings.Count)</div><div class="kpi-sub">$pausedRings paused</div></div>
  <div class="kpi"><div class="kpi-label">Published Apps</div><div class="kpi-value purple">$($apps.Count)</div><div class="kpi-sub">&nbsp;</div></div>
  <div class="kpi"><div class="kpi-label">App Reg Expiring</div><div class="kpi-value $(if($expiringSoon -gt 0){'yellow'}else{'green'})">$expiringSoon</div><div class="kpi-sub">Within 30 days</div></div>
  <div class="kpi"><div class="kpi-label">Enroll Failures</div><div class="kpi-value $(if($enrollFails.Count -gt 0){'red'}else{'green'})">$($enrollFails.Count)</div><div class="kpi-sub">Last 24 hours</div></div>
</div>

<div class="charts-grid">
  <div class="chart-card"><h2>Device Compliance</h2><canvas id="complianceChart" height="200"></canvas></div>
  <div class="chart-card"><h2>Devices by OS</h2><canvas id="osChart" height="200"></canvas></div>
</div>

<div class="alerts">
  <h2>&#x26A0;&#xFE0F; Active Alerts</h2>
$(if ($pausedRings -gt 0) { "  <div class='alert-item'><span class='badge badge-red'>CRITICAL</span><div><strong>$pausedRings update ring(s) paused</strong><div style='font-size:.8rem;color:#94a3b8;margin-top:.25rem'>Devices in paused rings are not receiving security patches.</div></div></div>" })
$(if ($nonCompliant -gt 0) { "  <div class='alert-item'><span class='badge badge-yellow'>WARNING</span><div><strong>$nonCompliant non-compliant device(s)</strong><div style='font-size:.8rem;color:#94a3b8;margin-top:.25rem'>These devices may be blocked from conditional access resources.</div></div></div>" })
$(if ($expiredCreds -gt 0) { "  <div class='alert-item'><span class='badge badge-red'>CRITICAL</span><div><strong>$expiredCreds expired app registration credential(s)</strong><div style='font-size:.8rem;color:#94a3b8;margin-top:.25rem'>Service accounts using these credentials will be failing authentication.</div></div></div>" })
$(if ($expiringSoon -gt 0) { "  <div class='alert-item'><span class='badge badge-yellow'>WARNING</span><div><strong>$expiringSoon app registration credential(s) expiring within 30 days</strong><div style='font-size:.8rem;color:#94a3b8;margin-top:.25rem'>Rotate before expiry to avoid outages.</div></div></div>" })
$(if ($staleCount -gt 0) { "  <div class='alert-item'><span class='badge badge-yellow'>WARNING</span><div><strong>$staleCount stale device(s)</strong><div style='font-size:.8rem;color:#94a3b8;margin-top:.25rem'>Devices have not synced in over 7 days.</div></div></div>" })
$(if ($unassignedPolicies -gt 0) { "  <div class='alert-item'><span class='badge badge-blue'>INFO</span><div><strong>$unassignedPolicies compliance policy(ies) unassigned</strong><div style='font-size:.8rem;color:#94a3b8;margin-top:.25rem'>These policies have no assignments and are not evaluating any devices.</div></div></div>" })
$(if ($pausedRings -eq 0 -and $nonCompliant -eq 0 -and $expiredCreds -eq 0 -and $expiringSoon -eq 0 -and $staleCount -eq 0 -and $unassignedPolicies -eq 0) { "  <div style='color:#4ade80;padding:.75rem 0'>&#x2705; No active alerts. Environment looks healthy.</div>" })
</div>

</main>
<footer>IAMinistrator &bull; IntuneToolKit by AliAlame &bull; https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit</footer>

<script>
new Chart(document.getElementById('complianceChart'),{type:'doughnut',data:{labels:['Compliant','Non-Compliant','Unknown'],datasets:[{data:[$compliant,$nonCompliant,$unknown],backgroundColor:['#4ade80','#f87171','#64748b'],borderWidth:0}]},options:{plugins:{legend:{position:'bottom',labels:{color:'#94a3b8'}}},cutout:'65%'}});
new Chart(document.getElementById('osChart'),{type:'bar',data:{labels:[$osLabels],datasets:[{data:[$osValues],backgroundColor:'#60a5fa',borderRadius:6}]},options:{plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#94a3b8'},grid:{color:'#1e2233'}},y:{ticks:{color:'#94a3b8'},grid:{color:'#1e2233'}}}}});
</script>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Status "Dashboard written to: $OutputPath" "Green"
Write-Host ""
