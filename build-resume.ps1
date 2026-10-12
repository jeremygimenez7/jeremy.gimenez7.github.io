# ===========================================================================
# build-resume.ps1
# Rebuilds assets/resume.pdf from assets/resume-source.txt
#
# USAGE (from the portfolio folder):
#   powershell -ExecutionPolicy Bypass -File build-resume.ps1
#
# You only need to edit assets/resume-source.txt - not this script.
# ===========================================================================
$ErrorActionPreference = 'Stop'

$root     = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcPath  = Join-Path $root 'assets\resume-source.txt'
$outPath  = Join-Path $root 'assets\resume.pdf'

if (-not (Test-Path $srcPath)) {
  throw "Could not find $srcPath"
}

function Esc([string]$s) {
  # Escape the characters that are special inside PDF text strings.
  return ($s -replace '\\', '\\\\' -replace '\(', '\(' -replace '\)', '\)')
}

$sb = New-Object System.Text.StringBuilder
$y  = 752.0

foreach ($raw in (Get-Content -LiteralPath $srcPath)) {
  $line = $raw.TrimEnd()

  # Skip comment lines and the trailing marker
  if ($line -match '^\s*//') { continue }

  # Blank line = small vertical gap
  if ($line.Trim() -eq '') {
    $y -= 7
    continue
  }

  # Split on the FIRST pipe only, so "META|a | b | c" still works
  $idx = $line.IndexOf('|')
  if ($idx -lt 1) { continue }
  $style = $line.Substring(0, $idx).Trim().ToUpper()
  $text  = $line.Substring($idx + 1)

  switch ($style) {
    'TITLE' { $font = '/F2'; $size = 12.5; $y -= 5 }
    'SUB'   { $font = '/F2'; $size = 10.5 }
    'H'     { $font = '/F2'; $size = 12.5; $y -= 5 }
    'B'     { $font = '/F2'; $size = 10.5 }
    'META'  { $font = '/F1'; $size = 9 }
    default { $font = '/F1'; $size = 10 }   # 'T' and anything unknown
  }

  [void]$sb.Append("BT $font $size Tf 60 $y Td ($(Esc $text)) Tj ET`n")
  $y -= 14
}

if ($y -lt 40) {
  Write-Warning "Content is close to the bottom of the page (y=$([math]::Round($y,1))). Consider trimming a few lines."
}

$content      = $sb.ToString()
$contentBytes = [System.Text.Encoding]::ASCII.GetBytes($content)

# ---- assemble PDF objects ----
$objects = New-Object System.Collections.ArrayList
[void]$objects.Add("<< /Type /Catalog /Pages 2 0 R >>")
[void]$objects.Add("<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
[void]$objects.Add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>")
[void]$objects.Add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
[void]$objects.Add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
[void]$objects.Add("<< /Length $($contentBytes.Length) >>`nstream`n$content`nendstream")

# ---- write with correct cross-reference offsets ----
$ms     = New-Object System.IO.MemoryStream
$writer = New-Object System.IO.StreamWriter($ms, [System.Text.Encoding]::ASCII)
$writer.NewLine = "`n"

$writer.Write("%PDF-1.4`n"); $writer.Flush()

$offsets = @()
for ($i = 0; $i -lt $objects.Count; $i++) {
  $offsets += $ms.Length
  $writer.Write("$($i + 1) 0 obj`n$($objects[$i])`nendobj`n")
  $writer.Flush()
}

$xrefPos = $ms.Length
$writer.Write("xref`n0 $($objects.Count + 1)`n")
$writer.Write("0000000000 65535 f `n")
foreach ($off in $offsets) { $writer.Write(("{0:D10} 00000 n `n" -f [int]$off)) }
$writer.Write("trailer`n<< /Size $($objects.Count + 1) /Root 1 0 R >>`nstartxref`n$xrefPos`n%%EOF`n")
$writer.Flush()

[System.IO.File]::WriteAllBytes($outPath, $ms.ToArray())
$writer.Dispose(); $ms.Dispose()

Write-Host "Rebuilt $outPath ($([int](Get-Item $outPath).Length) bytes)" -ForegroundColor Green
