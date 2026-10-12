<#
    ============================================================================
    sync-projects.ps1  -  copy the standalone project tools into this portfolio
    ----------------------------------------------------------------------------
    The portfolio publishes its OWN copy of each project tool inside
    projects\, because that is what visitors open when they click
    "Open the tool". A website cannot reach folders outside itself.

    So: if you edit a project in its original folder, run this script to refresh
    the copy the portfolio serves, before you publish the site.

    Original folders it looks for, next to this portfolio folder:
        Phishing-Analyser   ->  projects\phishing-email-analyser
        Network-Tool        ->  projects\network-traffic-triage
        Windows-Events      ->  projects\windows-event-triage

    The case-study pages (projects\phishing-email-analyser.html etc.) are NOT
    touched by this script - they are your write-ups, not generated files.

    HOW TO RUN
      Right-click this file and choose "Run with PowerShell", or open a terminal
      in the portfolio folder and run:
          powershell -ExecutionPolicy Bypass -File sync-projects.ps1
    ============================================================================
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$documents = Split-Path -Parent $here
$dest = Join-Path $here 'projects'

$map = [ordered]@{
    'Phishing-Analyser' = 'phishing-email-analyser'
    'Network-Tool'      = 'network-traffic-triage'
    'Windows-Events'    = 'windows-event-triage'
}

Write-Host ''
Write-Host 'Syncing the three project tools into the portfolio'
Write-Host ("Target folder: $dest")
Write-Host ''

foreach ($source in $map.Keys) {
    $from = Join-Path $documents $source
    $to = Join-Path $dest $map[$source]

    if (-not (Test-Path $from)) {
        Write-Warning "Source folder not found, skipped: $from"
        continue
    }

    if (Test-Path $to) { Remove-Item -Recurse -Force $to }
    Copy-Item -Recurse -Force $from $to

    $count = (Get-ChildItem -Recurse -File $to).Count
    Write-Host ("  {0,-20} ->  projects\{1,-26} {2,3} files" -f $source, $map[$source], $count)
}

Write-Host ''
Write-Host 'Done. Open index.html and use a project card to confirm it still works.'
Write-Host ''
