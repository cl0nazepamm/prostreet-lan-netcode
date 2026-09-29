"""NFS ProStreet (nfs.exe, v1.1 LAN patch build) - LAN race fixes.

1. Clock fix: in LAN races the main loop steps physics with a GetTickCount()-based network clock that only
   advances every 15.625 ms (own car judders). The 11 reads that make up that clock now use timeGetTime()
   (1 ms; the game already calls timeBeginPeriod(1)). IAT operand swaps only.
2. Send rate: each client sends OLMSG_CarState for its cars every INTERVAL = 1/15 s (15 Hz), so opponents
   are extrapolated for ~66 ms between updates. The scheduler's `fadd qword [0x9713D8]` (a 1/15 constant
   shared with unrelated code) is pointed at a private double in unused int3 padding holding 1/RATE.
   The 1/15 s resync threshold is left alone.
3. Large address aware: sets the LAA header bit (4 GB instead of 2 GB on 64-bit Windows), buying time
   against the netcode memory leak. --no-laa clears it again.

Usage: python nfs_lan_patch.py SRC_EXE DST_EXE [--rate HZ] [--no-laa]   (HZ=15 restores the stock send rate)
Refuses to touch anything that doesn't match the expected bytes.
"""
import struct, sys, argparse

IMAGE_BASE = 0x400000
GETTICKCOUNT_IAT, TIMEGETTIME_IAT = 0x96708C, 0x96750C
CLOCK_SITES = [(0x7B2701, b'\xFF\x15'), (0x7B2B48, b'\xFF\x15'), (0x7B2BA8, b'\xFF\x15'), (0x7B6457, b'\xFF\x15'),
               (0x7B64A7, b'\xFF\x15'), (0x7BB387, b'\xFF\x15'), (0x7BB7DE, b'\xFF\x15'), (0x7BB882, b'\x8B\x1D'),
               (0x7C496D, b'\xFF\x15'), (0x7C6E6F, b'\x8B\x1D'), (0x7C80AA, b'\xFF\x15')]
SEND_FADD = 0x7C13E7                       # fadd qword ptr [disp32]  (DC 05 disp32)
STOCK_INTERVAL = 0x9713D8                  # shared 1/15 double
RATE_CONST = 0x7C2338                      # 8 bytes of int3 padding after the ret at 0x7C2335


def file_offset(data, va):
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = struct.unpack_from('<H', data, pe + 6)[0]
    sec = pe + 24 + struct.unpack_from('<H', data, pe + 20)[0]
    for i in range(nsec):
        vsz, vaddr, rsz, raw = struct.unpack_from('<IIII', data, sec + 40 * i + 8)
        if vaddr <= va - IMAGE_BASE < vaddr + max(vsz, rsz):
            return va - IMAGE_BASE - vaddr + raw
    raise SystemExit(f'{va:#x} not in any section')


def patch(src, dst, rate, laa=True):
    data = bytearray(open(src, 'rb').read())
    at = lambda va, n: bytes(data[file_offset(data, va):file_offset(data, va) + n])
    def put(va, b):
        o = file_offset(data, va); data[o:o + len(b)] = b

    # --- 1. clock fix
    old, new = struct.pack('<I', GETTICKCOUNT_IAT), struct.pack('<I', TIMEGETTIME_IAT)
    states = []
    for va, op in CLOCK_SITES:
        cur = at(va, 6)
        if cur == op + new: states.append('new')
        elif cur == op + old: states.append('old')
        else: raise SystemExit(f'clock site {va:#x}: unexpected bytes {cur.hex()} - different nfs.exe build')
    if len(set(states)) != 1:
        raise SystemExit('clock sites partially patched - restore the original exe first')
    for va, op in CLOCK_SITES:
        put(va + 2, new)

    # --- 2. CarState send rate
    fadd = at(SEND_FADD, 6)
    stock_fadd = b'\xDC\x05' + struct.pack('<I', STOCK_INTERVAL)
    ours_fadd = b'\xDC\x05' + struct.pack('<I', RATE_CONST)
    const = at(RATE_CONST, 8)
    if fadd not in (stock_fadd, ours_fadd):
        raise SystemExit(f'send-rate site: unexpected bytes {fadd.hex()} - different nfs.exe build')
    if fadd == stock_fadd and const != b'\xCC' * 8:
        raise SystemExit('padding for the send-rate constant is not empty - different build')
    if rate == 15:
        put(SEND_FADD, stock_fadd); put(RATE_CONST, b'\xCC' * 8)
    else:
        put(RATE_CONST, struct.pack('<d', 1.0 / rate)); put(SEND_FADD, ours_fadd)

    # --- 3. large address aware (FILE_HEADER.Characteristics bit 0x20)
    chars = struct.unpack_from('<I', data, 0x3C)[0] + 22
    flags = struct.unpack_from('<H', data, chars)[0]
    struct.pack_into('<H', data, chars, flags | 0x20 if laa else flags & ~0x20)

    open(dst, 'wb').write(data)
    print(f'clock fix: {len(CLOCK_SITES)} sites ({"already" if states[0] == "new" else "newly"} patched); '
          f'CarState send rate: {rate} Hz; large address aware: {"on" if laa else "off"} -> {dst}')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('src'); ap.add_argument('dst')
    ap.add_argument('--rate', type=int, default=60, choices=[15, 20, 30, 40, 60])
    ap.add_argument('--no-laa', action='store_true')
    a = ap.parse_args()
    patch(a.src, a.dst, a.rate, laa=not a.no_laa)
