# dll-probe.ps1 — must run via 32-bit PowerShell:
#   C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -File <this script>
# Loads RdpCoreSccm.dll, calls RDPAPI_CreateInstance, reports result.

[bool]$is64 = [Environment]::Is64BitProcess
if ($is64) {
    Write-Error "Must run via 32-bit PowerShell (SysWOW64). Current process is 64-bit."
    exit 1
}
Write-Host "Running in 32-bit PowerShell (PID $PID, Is64BitProcess=$is64)" -ForegroundColor Green

$dllPath = "\\SHARE\RemoteTool\RdpCoreSccm.dll"
if (-not (Test-Path $dllPath)) {
    Write-Error "DLL not found at $dllPath"
    exit 1
}

# Avoid the [GUID] / System.Guid name collision by using a distinct struct name.
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class Kernel32 {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibraryW(string lpFileName);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hModule);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetLastError();
    [DllImport("ole32.dll")]
    public static extern int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);
    [DllImport("ole32.dll")]
    public static extern void CoUninitialize();
}

[StructLayout(LayoutKind.Sequential)]
public struct ComGuid {
    public uint  Data1;
    public ushort Data2;
    public ushort Data3;
    public byte B0; public byte B1; public byte B2; public byte B3;
    public byte B4; public byte B5; public byte B6; public byte B7;

    public static ComGuid From(Guid g) {
        var b = g.ToByteArray();
        return new ComGuid {
            Data1 = BitConverter.ToUInt32(b, 0),
            Data2 = BitConverter.ToUInt16(b, 4),
            Data3 = BitConverter.ToUInt16(b, 6),
            B0 = b[8], B1 = b[9], B2 = b[10], B3 = b[11],
            B4 = b[12], B5 = b[13], B6 = b[14], B7 = b[15],
        };
    }
}

public static class Marshalled {
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int RDPAPI_CreateInstance_Fn(
        IntPtr pPlatformContext,
        ref ComGuid rclsid,
        ref ComGuid riid,
        out IntPtr ppv);
}
"@ -ErrorAction Stop

# CoInitializeEx with COINIT_APARTMENTTHREADED (2) — matches CmRcViewer
$COINIT_APARTMENTTHREADED = 2
$hrInit = [Kernel32]::CoInitializeEx([IntPtr]::Zero, $COINIT_APARTMENTTHREADED)
Write-Host ("CoInitializeEx: HRESULT=0x{0:X8}" -f $hrInit)

# Load DLL
$h = [Kernel32]::LoadLibraryW($dllPath)
if ($h -eq [IntPtr]::Zero) {
    Write-Error "LoadLibraryW failed: WinError $([Kernel32]::GetLastError())"
    exit 1
}
Write-Host ("LoadLibraryW: handle=0x{0:x8}" -f [int64]$h) -ForegroundColor Green

$proc = [Kernel32]::GetProcAddress($h, "RDPAPI_CreateInstance")
if ($proc -eq [IntPtr]::Zero) {
    Write-Error "GetProcAddress failed: WinError $([Kernel32]::GetLastError())"
    exit 1
}
Write-Host ("RDPAPI_CreateInstance @ 0x{0:x8}" -f [int64]$proc) -ForegroundColor Green

$delegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $proc, [Marshalled+RDPAPI_CreateInstance_Fn])

# Real CLSIDs/IIDs extracted from CmRcViewer.exe binary at known RVAs.
$CLSID_RDPRuntimeSTAContext = [ComGuid]::From([Guid]::Parse('fb332ae7-0055-4208-92b7-20410ca8382b'))
$IID_IUnknown               = [ComGuid]::From([Guid]::Parse('00000000-0000-0000-c000-000000000046'))

$ppv = [IntPtr]::Zero
Write-Host "`nCalling RDPAPI_CreateInstance(NULL, CLSID_RDPRuntimeSTAContext, IID_IUnknown, &ppv)..." -ForegroundColor Yellow
$clsid = $CLSID_RDPRuntimeSTAContext
$iid = $IID_IUnknown
$hr = $delegate.Invoke([IntPtr]::Zero, [ref]$clsid, [ref]$iid, [ref]$ppv)
$hrHex = '0x{0:X8}' -f $hr
if ($hr -eq 0) {
    Write-Host ("  HRESULT={0}  ppv=0x{1:x8}  SUCCESS" -f $hrHex, [int64]$ppv) -ForegroundColor Green
    if ($ppv -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::Release($ppv) | Out-Null
    }
} else {
    # Translate common HRESULTs
    $name = switch ($hr) {
        ([int]0x80040154) { 'REGDB_E_CLASSNOTREG' }
        ([int]0x80040111) { 'CLASS_E_CLASSNOTAVAILABLE' }
        ([int]0x80070057) { 'E_INVALIDARG' }
        ([int]0x8007007E) { 'ERROR_MOD_NOT_FOUND' }
        ([int]0x80004002) { 'E_NOINTERFACE' }
        ([int]0x80004005) { 'E_FAIL' }
        ([int]0x80070005) { 'E_ACCESSDENIED' }
        default { '?' }
    }
    Write-Host ("  HRESULT={0}  ({1})" -f $hrHex, $name) -ForegroundColor Red
}

[Kernel32]::FreeLibrary($h) | Out-Null
[Kernel32]::CoUninitialize()
Write-Host "`ndone."
