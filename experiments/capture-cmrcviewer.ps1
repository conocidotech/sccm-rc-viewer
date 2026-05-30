# capture-cmrcviewer.ps1
# Captures a CmRcViewer.exe session to disk so we can compare its wire
# bytes with what our Rust probe sends.
#
# RUN IN AN ADMIN POWERSHELL (right-click PowerShell → Run as administrator,
# or have an IT-collega click "Yes" on the UAC prompt for you).
#
# Steps performed:
#   1. Create capture session for TCP/2701 + remote IP 10.0.0.10 (TARGET-HOST)
#   2. Start the capture
#   3. WAIT — you connect once with CmRcViewer.exe (\\SHARE\...\RemoteTool\)
#   4. After disconnecting, press ENTER here
#   5. Capture stops, ETL is converted to pcapng
#
# Output: capture.pcapng in this folder. The script self-cleans pktmon
# filters on exit.

$ErrorActionPreference = 'Stop'

# Verify admin
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
   ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Must run as Administrator. Re-launch PowerShell with 'Run as administrator'."
    exit 1
}

$workdir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$etlPath   = Join-Path $workdir 'capture.etl'
$pcapPath  = Join-Path $workdir 'capture.pcapng'
$targetIp  = '10.0.0.10'
$targetPort = 2701

Write-Host "Capture target  : ${targetIp}:${targetPort}" -ForegroundColor Cyan
Write-Host "ETL output      : ${etlPath}" -ForegroundColor Cyan
Write-Host "pcapng output   : ${pcapPath}" -ForegroundColor Cyan
Write-Host ""

# Clean any prior runs
try { & pktmon stop 2>&1 | Out-Null } catch {}
try { & pktmon filter remove 2>&1 | Out-Null } catch {}

# Set filter — only packets to/from TARGET-HOST:2701
Write-Host "→ Adding pktmon filter…" -ForegroundColor Yellow
& pktmon filter add 'sccm-rc' -t TCP -p $targetPort --ip-address $targetIp 2>&1 | Out-Null
& pktmon filter list

# Start capture (full packet payloads, no truncation)
Write-Host ""
Write-Host "→ Starting capture (full packet payloads)…" -ForegroundColor Yellow
& pktmon start --capture --pkt-size 0 --file $etlPath --file-size 64 2>&1

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " CAPTURE IS LIVE. Now do the following in another window:" -ForegroundColor Green
Write-Host "   1. Run CmRcViewer.exe from \\SHARE\RemoteTool\" -ForegroundColor Green
Write-Host "   2. Connect to TARGET-HOST (retry if first attempt fails)" -ForegroundColor Green
Write-Host "   3. Once you see the green bar on the remote, close the viewer" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Read-Host "Press ENTER here when you've disconnected"

Write-Host ""
Write-Host "→ Stopping capture…" -ForegroundColor Yellow
& pktmon stop 2>&1 | Out-Null

Write-Host "→ Cleaning up filter…" -ForegroundColor Yellow
& pktmon filter remove 2>&1 | Out-Null

if (-not (Test-Path $etlPath)) {
    Write-Error "ETL file not created. Did the capture run?"
    exit 1
}
$etlSize = (Get-Item $etlPath).Length
Write-Host ("→ ETL captured: {0:N0} bytes" -f $etlSize) -ForegroundColor Cyan

# Convert ETL → pcapng so Wireshark / our parser can read it
Write-Host "→ Converting ETL → pcapng…" -ForegroundColor Yellow
& pktmon etl2pcap $etlPath -o $pcapPath 2>&1
if (Test-Path $pcapPath) {
    $pcapSize = (Get-Item $pcapPath).Length
    Write-Host ("→ pcapng written: {0:N0} bytes" -f $pcapSize) -ForegroundColor Green
} else {
    Write-Warning "pcapng conversion failed — try opening capture.etl directly in Wireshark."
}

Write-Host ""
Write-Host "Done. Hand the file to Claude:" -ForegroundColor Green
Write-Host "  $pcapPath" -ForegroundColor Green
