# ===========================================================================
# fix-encoding.ps1
# Repairs "double-encoded" (mojibake) text in the portfolio HTML files.
#
# WHY THIS EXISTS:
#   add-screenshots.ps1 used to read the case-study page with Get-Content
#   WITHOUT -Encoding UTF8. Windows PowerShell therefore decoded the UTF-8 file
#   as the system ANSI codepage, so every non-ASCII character was doubled up
#   when it was written back:
#
#       "·"  became  "Â·"        (section eyebrows, e.g. "01 Â· Overview")
#       "—"  became  "â€""        (em dashes throughout the prose)
#       "'"  became  "â€™"        (apostrophes)
#
#   add-screenshots.ps1 has now been fixed so it no longer causes this, but the
#   damage it already did is baked into the files. This script reverses it.
#
# USAGE (from the portfolio folder):
#   powershell -ExecutionPolicy Bypass -File fix-encoding.ps1
#
# It only ever replaces the exact damaged character sequences listed below, so
# correct text is never touched. It is safe to run more than once.
# ===========================================================================
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$utf8 = New-Object System.Text.UTF8Encoding($false)

# --- which files to check -------------------------------------------------
$targets = New-Object System.Collections.ArrayList
[void]$targets.Add((Join-Path $root 'index.html'))
[void]$targets.Add((Join-Path $root 'README.md'))
foreach ($p in Get-ChildItem -Path (Join-Path $root 'projects') -Filter *.html -File) {
  [void]$targets.Add($p.FullName)
}

# Build a string from character codes, so this script file itself stays pure
# ASCII and can never be misread by PowerShell.
function Seq([int[]]$codes) {
  $out = ''
  foreach ($c in $codes) { $out += [char]$c }
  return $out
}

# damaged sequence  ->  the character it was meant to be
$map = @(
  @{ bad = (Seq @(0xE2, 0x20AC, 0x201D)); good = (Seq @(0x2014)) },  # em dash
  @{ bad = (Seq @(0xE2, 0x20AC, 0x201C)); good = (Seq @(0x2013)) },  # en dash
  @{ bad = (Seq @(0xE2, 0x20AC, 0x2122)); good = (Seq @(0x2019)) },  # right single quote
  @{ bad = (Seq @(0xE2, 0x20AC, 0x02DC)); good = (Seq @(0x2018)) },  # left single quote
  @{ bad = (Seq @(0xE2, 0x20AC, 0x0153)); good = (Seq @(0x201C)) },  # left double quote
  @{ bad = (Seq @(0xE2, 0x20AC, 0x009D)); good = (Seq @(0x201D)) },  # right double quote
  @{ bad = (Seq @(0xE2, 0x20AC, 0x00A6)); good = (Seq @(0x2026)) },  # ellipsis
  @{ bad = (Seq @(0xE2, 0x20AC, 0x00A2)); good = (Seq @(0x2022)) },  # bullet
  @{ bad = (Seq @(0xE2, 0x2020, 0x2019)); good = (Seq @(0x2192)) },  # right arrow
  @{ bad = (Seq @(0xE2, 0x2020, 0x0090)); good = (Seq @(0x2190)) },  # left arrow
  @{ bad = (Seq @(0xC2, 0xB7));           good = (Seq @(0xB7))   },  # middle dot
  @{ bad = (Seq @(0xC2, 0xA9));           good = (Seq @(0xA9))   },  # copyright
  @{ bad = (Seq @(0xC3, 0xA9));           good = (Seq @(0xE9))   },  # e acute
  @{ bad = (Seq @(0xC2, 0xA0));           good = (Seq @(0x20))   }   # nbsp -> space
)

$repaired = 0

foreach ($path in $targets) {
  if (-not (Test-Path -LiteralPath $path)) { continue }

  $text = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
  $before = $text

  # Loop until a whole pass changes nothing, so layered damage is fully undone.
  do {
    $prev = $text
    foreach ($pair in $map) { $text = $text.Replace($pair.bad, $pair.good) }
  } while ($text -ne $prev)

  if ($text -ne $before) {
    [System.IO.File]::WriteAllText($path, $text, $utf8)
    Write-Host ("Repaired  {0}" -f (Split-Path -Leaf $path)) -ForegroundColor Green
    $repaired++
  } else {
    Write-Host ("Clean     {0}" -f (Split-Path -Leaf $path)) -ForegroundColor DarkGray
  }
}

Write-Host ''
if ($repaired -gt 0) {
  Write-Host "$repaired file(s) repaired. Reload the site in your browser to confirm." -ForegroundColor Green
} else {
  Write-Host 'Nothing needed repairing - all files are already clean.' -ForegroundColor Green
}
