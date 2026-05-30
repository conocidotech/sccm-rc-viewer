# Source this before running cargo: `. .\env.ps1`
# Sets PATH for Rust + the WinLibs MinGW-w64 linker/dlltool.

$rustBin = "$env:USERPROFILE\.cargo\bin"

$winlibsPkg = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Directory -Filter '*WinLibs*POSIX*UCRT*' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $winlibsPkg) {
    Write-Error "WinLibs MinGW not found. Run: winget install --id BrechtSanders.WinLibs.POSIX.UCRT --scope user"
    return
}
$winlibsBin = (Get-ChildItem $winlibsPkg.FullName -Recurse -Filter 'gcc.exe' -File | Select-Object -First 1).DirectoryName

$env:Path = "$winlibsBin;$rustBin;$env:Path"
Write-Host "Rust + MinGW on PATH. Try: cargo build" -ForegroundColor Green
Write-Host "  rustc: $(rustc --version)"
Write-Host "  gcc:   $(gcc --version | Select-Object -First 1)"
