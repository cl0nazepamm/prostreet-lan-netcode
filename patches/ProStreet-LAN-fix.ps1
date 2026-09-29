# NFS ProStreet - LAN race fixes for nfs.exe (v1.1 LAN patch build)
#
# 1. Clock fix: LAN races step physics with a GetTickCount() clock that only advances every ~15.6 ms,
#    so your own car judders. 11 spots are switched to timeGetTime() (1 ms resolution).
# 2. Send rate: your car's position is sent to others 15 times a second; this raises it (default 60),
#    so opponents are guessed for less time between updates. Both players need it.
# 3. Large address aware: lets the game use 4 GB instead of 2 GB (the LAN netcode leaks memory while
#    racing, so this doubles the time before it runs out). -NoLAA turns it off again.
#
# Usage: put this file next to nfs.exe, close the game, then run:
#   powershell -ExecutionPolicy Bypass -File .\ProStreet-LAN-fix.ps1            (60 Hz)
#   powershell -ExecutionPolicy Bypass -File .\ProStreet-LAN-fix.ps1 -Rate 30   (15 = stock rate)
# Works on the original exe or an already patched one. Backup: nfs.exe.before-lanfix
param([string]$ExePath = (Join-Path $PSScriptRoot 'nfs.exe'), [ValidateSet(15, 20, 30, 40, 60)][int]$Rate = 60,
      [switch]$NoLAA)

$ErrorActionPreference = 'Stop'
$ImageBase = 0x400000
$Old = [BitConverter]::GetBytes([uint32]0x96708C)   # GetTickCount IAT slot
$New = [BitConverter]::GetBytes([uint32]0x96750C)   # timeGetTime IAT slot
$Sites = @(
    @(0x7B2701, 0xFF, 0x15), @(0x7B2B48, 0xFF, 0x15), @(0x7B2BA8, 0xFF, 0x15), @(0x7B6457, 0xFF, 0x15),
    @(0x7B64A7, 0xFF, 0x15), @(0x7BB387, 0xFF, 0x15), @(0x7BB7DE, 0xFF, 0x15), @(0x7BB882, 0x8B, 0x1D),
    @(0x7C496D, 0xFF, 0x15), @(0x7C6E6F, 0x8B, 0x1D), @(0x7C80AA, 0xFF, 0x15))
$SendFadd = 0x7C13E7                                    # fadd qword ptr [disp32]
$StockFadd = [byte[]](@(0xDC, 0x05) + [BitConverter]::GetBytes([uint32]0x9713D8))
$OurFadd = [byte[]](@(0xDC, 0x05) + [BitConverter]::GetBytes([uint32]0x7C2338))
$RateConst = 0x7C2338                                   # 8 bytes of unused int3 padding
$Pad = [byte[]](@(0xCC) * 8)

if (-not (Test-Path $ExePath)) { throw "nfs.exe not found at $ExePath" }
if (Get-Process nfs -ErrorAction SilentlyContinue) { throw 'Close the game first.' }
$data = [IO.File]::ReadAllBytes($ExePath)

function Get-FileOffset([byte[]]$d, [int]$va) {
    $pe = [BitConverter]::ToInt32($d, 0x3C)
    $n = [BitConverter]::ToUInt16($d, $pe + 6)
    $sec = $pe + 24 + [BitConverter]::ToUInt16($d, $pe + 20)
    $rva = $va - $ImageBase
    for ($i = 0; $i -lt $n; $i++) {
        $h = $sec + 40 * $i
        $vsz = [BitConverter]::ToUInt32($d, $h + 8); $vaddr = [BitConverter]::ToUInt32($d, $h + 12)
        $rsz = [BitConverter]::ToUInt32($d, $h + 16); $raw = [BitConverter]::ToUInt32($d, $h + 20)
        if ($rva -ge $vaddr -and $rva -lt $vaddr + [Math]::Max($vsz, $rsz)) { return [int]($rva - $vaddr + $raw) }
    }
    throw ('address 0x{0:X} not found' -f $va)
}
function Test-Bytes([byte[]]$d, [int]$va, [byte[]]$expect) {
    $o = Get-FileOffset $d $va
    for ($i = 0; $i -lt $expect.Length; $i++) { if ($d[$o + $i] -ne $expect[$i]) { return $false } }
    return $true
}
function Set-Bytes([byte[]]$d, [int]$va, [byte[]]$b) {
    $o = Get-FileOffset $d $va
    for ($i = 0; $i -lt $b.Length; $i++) { $d[$o + $i] = $b[$i] }
}

# verify everything before changing anything
$clockNew = 0; $clockOld = 0
foreach ($s in $Sites) {
    $op = [byte[]]@($s[1], $s[2])
    if (Test-Bytes $data $s[0] ($op + $New)) { $clockNew++ }
    elseif (Test-Bytes $data $s[0] ($op + $Old)) { $clockOld++ }
    else { throw ('Unexpected bytes at 0x{0:X}: different nfs.exe build, nothing was changed.' -f $s[0]) }
}
if ($clockNew -gt 0 -and $clockOld -gt 0) { throw 'Clock fix partially applied - restore the original exe first.' }
$faddStock = Test-Bytes $data $SendFadd $StockFadd
if (-not $faddStock -and -not (Test-Bytes $data $SendFadd $OurFadd)) { throw 'Unexpected bytes at the send-rate site: different build, nothing was changed.' }
if ($faddStock -and -not (Test-Bytes $data $RateConst $Pad)) { throw 'Send-rate padding is not empty: different build, nothing was changed.' }

if (-not (Test-Path "$ExePath.before-lanfix")) { Copy-Item $ExePath "$ExePath.before-lanfix" }   # keep the first backup
foreach ($s in $Sites) { Set-Bytes $data ($s[0] + 2) $New }
if ($Rate -eq 15) { Set-Bytes $data $SendFadd $StockFadd; Set-Bytes $data $RateConst $Pad }
else { Set-Bytes $data $RateConst ([BitConverter]::GetBytes([double](1.0 / $Rate))); Set-Bytes $data $SendFadd $OurFadd }
$chars = [BitConverter]::ToInt32($data, 0x3C) + 22        # FILE_HEADER.Characteristics
if ($NoLAA) { $data[$chars] = $data[$chars] -band 0xDF } else { $data[$chars] = $data[$chars] -bor 0x20 }
[IO.File]::WriteAllBytes($ExePath, $data)
Write-Host "Clock fix applied, car update rate $Rate Hz, 4 GB mode $(if ($NoLAA) { 'off' } else { 'on' }). Backup: $ExePath.before-lanfix"
