"""Find per-frame counters in nfs.exe: snapshot .data/.bss, wait, snapshot again, keep dwords that grew
by a frame-rate-like amount, repeat to keep only steady ones.  Read-only (ReadProcessMemory)."""
import ctypes, ctypes.wintypes as w, time, sys, struct, subprocess

k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = w.HANDLE
k.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

def pid_of(name):
    out = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {name}', '/FO', 'CSV', '/NH'], capture_output=True, text=True).stdout
    return int(out.split('","')[1]) if name in out else None

pid = pid_of('nfs.exe')
h = k.OpenProcess(0x0010 | 0x0400, False, pid)
if not h:
    sys.exit(f'OpenProcess failed {ctypes.get_last_error()}')
LO, HI = 0x64A000, 0x64A000 + 0x5C6000          # .data (incl. bss) of nfs.exe

def snap():
    out = bytearray(HI - LO)
    for a in range(LO, HI, 0x1000):
        buf = ctypes.create_string_buffer(0x1000); got = ctypes.c_size_t()
        if k.ReadProcessMemory(h, a, buf, 0x1000, ctypes.byref(got)):
            out[a - LO:a - LO + 0x1000] = buf.raw
    return out

def dwords(b):
    import array
    arr = array.array('I'); arr.frombytes(bytes(b)); return arr

samples = []
for i in range(4):
    t = time.perf_counter(); samples.append((t, dwords(snap()))); time.sleep(1.0)
cands = None
for (t0, a), (t1, b) in zip(samples, samples[1:]):
    dt = t1 - t0
    rate = {i: (b[i] - a[i]) / dt for i in (range(len(a)) if cands is None else cands)}
    cands = {i for i, r in rate.items() if 20 <= r <= 1000}
rates = {}
for i in cands:
    rs = [(samples[j + 1][1][i] - samples[j][1][i]) / (samples[j + 1][0] - samples[j][0]) for j in range(3)]
    if max(rs) - min(rs) < 0.15 * max(rs):
        rates[LO + 4 * i] = rs
for addr, rs in sorted(rates.items(), key=lambda x: -x[1][0])[:40]:
    print(f'{addr:#010x}  per-second: ' + ', '.join(f'{r:7.1f}' for r in rs))
print('pid', pid, 'candidates', len(rates))
