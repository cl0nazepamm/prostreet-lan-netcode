"""Binary patcher for the NFS ProStreet LAN server (bombd.exe / rebroadcasterlan.exe, Dec 2007 build).

Patches (each site is verified against the expected original bytes first):
  rebroadcasterlan.exe
    af      socket(AF_UNSPEC,...) -> AF_INET in netcodeWinsockPlatUDPSocket::Open (Win10/11 fix)
    sleep   main loop Sleep(10) -> Sleep(SLEEP_MS)  (both idle branches)
    timer   entry-point stub: SetProcessInformation(ProcessPowerThrottling, honor timer res)
            + timeBeginPeriod(1)
    log     re-enable compiled-out debug log (stub -> printf)  [debug builds only]
  bombd.exe
    sleep   main loop Sleep(10) -> Sleep(SLEEP_MS)
    timer   same entry-point stub
"""
import struct, sys, hashlib, argparse
import pefile

REBROADCASTER_MD5 = 'bb4b9c7e58fbd7ad8d395c7e179f4542'
BOMBD_MD5 = 'bc49ce807cd58f35177c526be2247f77'


class Patcher:
    def __init__(self, path):
        self.pe = pefile.PE(path)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = bytearray(open(path, 'rb').read())
        self.text = [s for s in self.pe.sections if s.Name.startswith(b'.text')][0]

    def off(self, va):
        return self.pe.get_offset_from_rva(va - self.base)

    def expect(self, va, orig):
        o = self.off(va)
        got = bytes(self.data[o:o + len(orig)])
        if got != orig:
            raise SystemExit(f'unexpected bytes at {va:#x}: {got.hex()} != {orig.hex()}')

    def put(self, va, new, orig=None):
        if orig is not None:
            self.expect(va, orig)
        o = self.off(va)
        self.data[o:o + len(new)] = new

    def iat(self, name):
        for e in self.pe.DIRECTORY_ENTRY_IMPORT:
            for i in e.imports:
                if i.name and i.name.decode() == name:
                    return i.address
        raise KeyError(name)

    def cave(self, size):
        """Space in the .text raw padding past VirtualSize; grows VirtualSize to cover it."""
        t = self.text
        start_rva = (t.VirtualAddress + t.Misc_VirtualSize + 0x3F) & ~0xF
        end_rva = t.VirtualAddress + t.SizeOfRawData
        if start_rva + size > end_rva:
            raise SystemExit('not enough .text padding for code cave')
        o = self.pe.get_offset_from_rva(start_rva)
        if any(self.data[o:o + size]):
            raise SystemExit('code cave region is not empty')
        # grow VirtualSize (section header field) so the loader maps the cave bytes
        hdr = t.get_file_offset() + 8
        new_vs = start_rva + size - t.VirtualAddress
        struct.pack_into('<I', self.data, hdr, max(new_vs, t.Misc_VirtualSize))
        return self.base + start_rva

    def set_entry(self, va):
        o = self.pe.OPTIONAL_HEADER.get_file_offset() + 16  # AddressOfEntryPoint
        struct.pack_into('<I', self.data, o, va - self.base)

    def clear_checksum(self):
        o = self.pe.OPTIONAL_HEADER.get_file_offset() + 64
        struct.pack_into('<I', self.data, o, 0)

    def save(self, path):
        open(path, 'wb').write(self.data)


def rel32(src_next, dst):
    return struct.pack('<i', dst - src_next)


def timer_stub(p, cave_va, orig_ep):
    """x86 stub run before the CRT entry point:
         SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling,
                               {Version=1, ControlMask=IGNORE_TIMER_RESOLUTION, StateMask=0})
           -> Windows 11 must honor this process's timer resolution even with no visible window
         timeBeginPeriod(1)  -> Sleep()/waits get 1 ms granularity instead of 15.6 ms
       Every call is looked up at runtime and skipped if missing (older Windows).
    """
    LoadLibraryA, GetProcAddress = p.iat('LoadLibraryA'), p.iat('GetProcAddress')
    strings = [b'kernel32.dll\0', b'SetProcessInformation\0', b'winmm.dll\0', b'timeBeginPeriod\0']
    code_len = 0x70
    addrs, blob, a = [], b'', cave_va + code_len
    for s in strings:
        addrs.append(a); blob += s; a += len(s)
    k32, spi, winmm, tbp = addrs

    c = bytearray()
    c += b'\x60'                                             # pushad
    c += b'\x68' + struct.pack('<I', k32)                    # push "kernel32.dll"
    c += b'\xFF\x15' + struct.pack('<I', LoadLibraryA)       # call [LoadLibraryA]
    c += b'\x85\xC0'                                         # test eax,eax
    j1 = len(c); c += b'\x74\x00'                            # jz skip_spi
    c += b'\x68' + struct.pack('<I', spi)                    # push "SetProcessInformation"
    c += b'\x50'                                             # push eax
    c += b'\xFF\x15' + struct.pack('<I', GetProcAddress)     # call [GetProcAddress]
    c += b'\x85\xC0'                                         # test eax,eax
    j2 = len(c); c += b'\x74\x00'                            # jz skip_spi
    c += b'\x6A\x00\x6A\x04\x6A\x01'                         # push 0 (StateMask), 4 (ControlMask), 1 (Version)
    c += b'\x89\xE1'                                         # mov ecx,esp
    c += b'\x6A\x0C\x51\x6A\x04\x6A\xFF'                     # push 12, ecx, ProcessPowerThrottling(4), -1
    c += b'\xFF\xD0'                                         # call eax (stdcall)
    c += b'\x83\xC4\x0C'                                     # add esp,12
    skip_spi = len(c)
    c += b'\x68' + struct.pack('<I', winmm)                  # push "winmm.dll"
    c += b'\xFF\x15' + struct.pack('<I', LoadLibraryA)
    c += b'\x85\xC0'
    j3 = len(c); c += b'\x74\x00'                            # jz done
    c += b'\x68' + struct.pack('<I', tbp)                    # push "timeBeginPeriod"
    c += b'\x50'
    c += b'\xFF\x15' + struct.pack('<I', GetProcAddress)
    c += b'\x85\xC0'
    j4 = len(c); c += b'\x74\x00'                            # jz done
    c += b'\x6A\x01\xFF\xD0'                                 # push 1 ; call eax
    done = len(c)
    c += b'\x61'                                             # popad
    c += b'\xE9' + rel32(cave_va + len(c) + 5, orig_ep)      # jmp original entry point
    for j, tgt in ((j1, skip_spi), (j2, skip_spi), (j3, done), (j4, done)):
        c[j + 1] = tgt - (j + 2)
    assert len(c) <= code_len, len(c)
    c += b'\xCC' * (code_len - len(c))
    return bytes(c) + blob


def patch_rebroadcaster(src, dst, af=True, sleep_ms=None, timer=True, log=False):
    if hashlib.md5(open(src, 'rb').read()).hexdigest() != REBROADCASTER_MD5:
        raise SystemExit('rebroadcasterlan.exe is not the expected Dec 2007 build')
    p = Patcher(src)
    orig_ep = p.base + p.pe.OPTIONAL_HEADER.AddressOfEntryPoint
    sock_iat = p.iat('socket')
    size = 0x20 + (0xB0 if timer else 0)
    cave = p.cave(size)
    if af:
        # cave: force af=AF_INET for socket() and hints.ai_family=AF_INET for getaddrinfo()
        stub = (b'\xC7\x44\x24\x04\x02\x00\x00\x00'      # mov dword [esp+4],2    (socket af)
                b'\xC7\x44\x24\x18\x02\x00\x00\x00'      # mov dword [esp+0x18],2 (hints.ai_family)
                b'\xFF\x25' + struct.pack('<I', sock_iat))  # jmp [socket]
        p.put(cave, stub.ljust(0x20, b'\xCC'))
        p.put(0x489A41, b'\xE8' + rel32(0x489A46, cave) + b'\x90',
              orig=b'\xFF\x15' + struct.pack('<I', sock_iat))
    if sleep_ms is not None:
        p.put(0x40376E, bytes([0x6A, sleep_ms]), orig=b'\x6A\x0A')   # idle-object Sleep(10)
        p.put(0x403789, bytes([0x6A, sleep_ms]), orig=b'\x6A\x0A')   # direct Sleep(10)
    if timer:
        stub_va = cave + 0x20
        p.put(stub_va, timer_stub(p, stub_va, orig_ep))
        p.set_entry(stub_va)
    if log:
        p.put(0x4473E0, b'\xFF\x25' + struct.pack('<I', p.iat('printf')), orig=b'\xC3\xCC\xCC\xCC\xCC\xCC')
    p.clear_checksum()
    p.save(dst)


def patch_bombd(src, dst, sleep_ms=None, timer=True):
    if hashlib.md5(open(src, 'rb').read()).hexdigest() != BOMBD_MD5:
        raise SystemExit('bombd.exe is not the expected Dec 2007 build')
    p = Patcher(src)
    orig_ep = p.base + p.pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if sleep_ms is not None:
        p.put(0x40241C, bytes([0x6A, sleep_ms]), orig=b'\x6A\x0A')   # main loop Sleep(10)
    if timer:
        cave = p.cave(0xB0)
        p.put(cave, timer_stub(p, cave, orig_ep))
        p.set_entry(cave)
    p.clear_checksum()
    p.save(dst)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('which', choices=['rebroadcaster', 'bombd'])
    ap.add_argument('src'); ap.add_argument('dst')
    ap.add_argument('--no-af', action='store_true')
    ap.add_argument('--no-timer', action='store_true')
    ap.add_argument('--sleep', type=int, default=None)
    ap.add_argument('--log', action='store_true')
    a = ap.parse_args()
    if a.which == 'rebroadcaster':
        patch_rebroadcaster(a.src, a.dst, af=not a.no_af, sleep_ms=a.sleep, timer=not a.no_timer, log=a.log)
    else:
        patch_bombd(a.src, a.dst, sleep_ms=a.sleep, timer=not a.no_timer)
    print('wrote', a.dst)
