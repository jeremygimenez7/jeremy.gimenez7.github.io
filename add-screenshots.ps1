# ===========================================================================
# add-screenshots.ps1
# Resizes the lab screenshots you drop in and wires them into the case study.
#
# WHY THIS EXISTS:
#   Raw screen captures are often several MB each. The website only needs
#   ~1600px-wide JPEGs, which load fast and keep the folder small. This script
#   resizes each image for you and updates projects\wazuh-soc-lab.html so you
#   do not have to edit any HTML by hand.
#
# USAGE (from the portfolio folder):
#   powershell -ExecutionPolicy Bypass -File add-screenshots.ps1
#
# BEFORE YOU RUN IT:
#   1. REDACT each screenshot first: black out IP addresses, hostnames and
#      computer names, usernames, account names, Windows Security IDs (SIDs),
#      email addresses and anything else identifying. This is your job - the
#      script cannot do it for you.
#   2. Save the redacted images into:  assets\screenshots\_incoming\
#   3. Name each file so the script can tell which slot it belongs to. The file
#      name must contain the words listed below. Any image extension works
#      (.png .jpg .jpeg .bmp .gif):
#
#        contains "dashboard"               -> Wazuh SIEM Dashboard
#        contains "endpoint"                -> Windows Endpoint Security Event
#        contains "fim" + "events"          -> File Integrity Monitoring - Events
#        contains "details"                 -> FIM Alert Detail
#        contains "ubuntu"                  -> Ubuntu Server & Wazuh Installation
#        contains "workflow"                -> AI-Assisted SOC Workflow
#        contains "openai"                  -> AI-Assisted SOC Triage Report
#        contains "reports"                 -> Secure AI SOC Report Handling
#
#      So "01 wazuh dashboard overview.png", "wazuh-dashboard.png" and
#      "shot-wazuh-dashboard.png" all work equally well. Files that match
#      nothing are reported and left alone.
#
#   4. Run the script. It reports exactly what it used and what it skipped.
#
# You only need to edit this file if you want a different image width/quality.
# ===========================================================================
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$root     = Split-Path -Parent $MyInvocation.MyCommand.Path
$inDir    = Join-Path $root 'assets\screenshots\_incoming'
$outDir   = Join-Path $root 'assets\screenshots'
$pagePath = Join-Path $root 'projects\wazuh-soc-lab.html'

$maxWidth = 1600   # pixels - images wider than this are scaled down
$quality  = 82     # JPEG quality, 1-100 (82 is a good size/quality balance)

# Each slot lists the words its file name must contain to be matched.
#   all = every word must appear somewhere in the file name (case-insensitive)
#   any = at least one of these words must also appear
# Words are matched against the file name with separators (- _ . ) treated as
# spaces, so "Wazuh SIEM Dashboard.png", "wazuh-dashboard.png" and
# "shot-wazuh-dashboard.png" all match the same slot.
$slots = [ordered]@{
  'shot-wazuh-dashboard'     = @{ all = @('dashboard') }
  'shot-windows-endpoint'    = @{ all = @('endpoint') }
  'shot-fim-events'          = @{ all = @('fim');      any = @('events') }
  'shot-fim-alert-detail'    = @{ all = @('details') }
  'shot-ubuntu-wazuh-install'= @{ all = @('ubuntu') }
  'shot-ai-soc-workflow'     = @{ all = @('workflow') }
  'shot-openai-soc'          = @{ all = @('openai') }
  'shot-secure-reports'      = @{ all = @('reports') }
}

if (-not (Test-Path $inDir)) {
  New-Item -ItemType Directory -Path $inDir -Force | Out-Null
  Write-Host "Created $inDir - put your redacted screenshots in there, then run this script again." -ForegroundColor Yellow
  exit 0
}

if (-not (Test-Path $pagePath)) { throw "Could not find $pagePath" }

$images = @(Get-ChildItem -Path $inDir -File | Where-Object { $_.Extension -match '^\.(png|jpe?g|bmp|gif|tiff?)$' })
if ($images.Count -eq 0) {
  Write-Host "No images found in $inDir" -ForegroundColor Yellow
  Write-Host "Add your redacted screenshots there (see the naming guide at the top of this script) and run it again." -ForegroundColor Yellow
  exit 0
}


function Get-JpegCodec {
  [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() |
    Where-Object { $_.MimeType -eq 'image/jpeg' } | Select-Object -First 1
}

$codec = Get-JpegCodec
$encParams = New-Object System.Drawing.Imaging.EncoderParameters 1
$encParams.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter(
  [System.Drawing.Imaging.Encoder]::Quality, [int64]$quality)

$used    = @()
$skipped = @()
$usedNames = New-Object System.Collections.ArrayList
# -Encoding UTF8 is REQUIRED: without it Windows PowerShell decodes this UTF-8
# file as the system ANSI codepage, so every non-ASCII character (the middle dot
# in section eyebrows, em dashes, curly quotes) gets mangled and written back.
$html    = Get-Content -LiteralPath $pagePath -Raw -Encoding UTF8
$changed = $false

foreach ($slot in $slots.Keys) {
  $rule = $slots[$slot]

  $match = $images | Where-Object {
    if ($usedNames -contains $_.FullName) { return $false }

    $name = [System.IO.Path]::GetFileNameWithoutExtension($_.Name).ToLower() -replace '[_.\-]+', ' '
    $ok = $true

    foreach ($word in $rule.all) {
      if ($name -notlike "*$word*") { $ok = $false }
    }

    if ($ok -and $rule.any) {
      $hit = $false
      foreach ($word in $rule.any) {
        if ($name -like "*$word*") { $hit = $true }
      }
      if (-not $hit) { $ok = $false }
    }

    $ok
  } | Select-Object -First 1

  if (-not $match) {
    $skipped += "$slot  (needs a file name containing: $(($rule.all + $rule.any) -join ' + '))"
    continue
  }

  [void]$usedNames.Add($match.FullName)

  # --- resample + write JPEG ---
  $src = [System.Drawing.Image]::FromFile($match.FullName)
  try {
    $w = $src.Width
    $h = $src.Height
    if ($w -gt $maxWidth) {
      $newW = $maxWidth
      $newH = [int][math]::Round($h * ($maxWidth / $w))
    } else {
      $newW = $w
      $newH = $h
    }

    $bmp = New-Object System.Drawing.Bitmap $newW, $newH
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    try {
      $gfx.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
      $gfx.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
      $gfx.PixelOffsetMode   = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
      $gfx.DrawImage($src, 0, 0, $newW, $newH)
    } finally { $gfx.Dispose() }

    $outPath = Join-Path $outDir "$slot.jpg"
    try {
      $bmp.Save($outPath, $codec, $encParams)
    } finally { $bmp.Dispose() }

    $kb = [int]((Get-Item $outPath).Length / 1KB)
    $used += ("{0}.jpg  <-  {1}  ({2}x{3} -> {4}x{5}, {6} KB)" -f $slot, $match.Name, $w, $h, $newW, $newH, $kb)
  } finally { $src.Dispose() }

  # --- point the page at the new .jpg instead of the .svg placeholder ---
  $before = $html
  $html = $html.Replace("screenshots/$slot.svg", "screenshots/$slot.jpg")
  if ($html -ne $before) { $changed = $true }
}

if ($changed) {
  [System.IO.File]::WriteAllText($pagePath, $html, (New-Object System.Text.UTF8Encoding $false))
}

Write-Host ""
if ($used.Count) {
  Write-Host "Added $($used.Count) screenshot(s):" -ForegroundColor Green
  $used | ForEach-Object { Write-Host "  $_" }
} else {
  Write-Host "Nothing was added - no file name matched a slot." -ForegroundColor Yellow
}

if ($skipped.Count) {
  Write-Host ""
  Write-Host "Still using the placeholder for:" -ForegroundColor Yellow
  $skipped | ForEach-Object { Write-Host "  $_" }
}

if ($changed) {
  Write-Host ""
  Write-Host "Updated projects\wazuh-soc-lab.html to use the new images." -ForegroundColor Green
}

Write-Host ""
Write-Host "Reminder: keep assets\screenshots\_incoming out of anything you publish." -ForegroundColor Cyan
