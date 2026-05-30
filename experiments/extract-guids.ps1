# Extract 16-byte GUID values at specific RVAs in a PE.
param(
    [string]$PEPath = '\\SHARE\RemoteTool\CmRcViewer.exe'
)
$bytes = [IO.File]::ReadAllBytes($PEPath)

function U16($o) { [BitConverter]::ToUInt16($bytes, $o) }
function U32($o) { [BitConverter]::ToUInt32($bytes, $o) }

# Parse PE header → section table
$elfanew = U32 0x3C
$fileHdr = $elfanew + 4
$nSects  = U16 ($fileHdr + 2)
$optSize = U16 ($fileHdr + 16)
$optHdr  = $fileHdr + 20
$magic   = U16 $optHdr
$is64    = $magic -eq 0x20b
$imageBase = if ($is64) { [BitConverter]::ToUInt64($bytes, $optHdr + 24) } else { U32 ($optHdr + 28) }
$sectHdr = $optHdr + $optSize
$sections = @()
for ($i = 0; $i -lt $nSects; $i++) {
    $h = $sectHdr + 40 * $i
    $sections += [pscustomobject]@{
        V  = U32 ($h + 12)
        VS = U32 ($h + 8)
        R  = U32 ($h + 20)
        RS = U32 ($h + 16)
    }
}
function Rva2Off($rva) {
    foreach ($s in $sections) {
        if ($rva -ge $s.V -and $rva -lt $s.V + [Math]::Max($s.VS, $s.RS)) {
            return $s.R + ($rva - $s.V)
        }
    }
    -1
}

function ReadGuidAt($va) {
    $rva = $va - $imageBase
    $off = Rva2Off $rva
    if ($off -lt 0) { return "<invalid VA 0x$($va.ToString('x'))>" }
    $g = [Guid]::new([byte[]]($bytes[$off..($off + 15)]))
    return $g.ToString()
}

# Addresses we found in Ghidra decomp:
$targets = @(
    @{ Name = 'CLSID for top-level RDPAPI_CreateInstance (RDPRuntimeSTAContext)'; VA = 0x0040165c }
    @{ Name = 'IID for top-level call                  (IRDPRuntimeSTAContext?)'; VA = 0x004018e4 }
    @{ Name = 'CLSID for second call    (RDPWLCCLAxHost)';                       VA = 0x0040166c }
    @{ Name = 'IID for second call      (IRDPWLCCLAxHost)';                      VA = 0x00401750 }
)

foreach ($t in $targets) {
    $g = ReadGuidAt $t.VA
    Write-Host ("  0x{0:x8}  {1,-60}  {{{2}}}" -f $t.VA, $t.Name, $g)
}
