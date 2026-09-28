"""Log private memory of bombd / rebroadcasterlan / nfs every 10 s (plus the game's race state), read-only.
Usage: python memlog.py OUTFILE START_DELAY_S DURATION_MIN"""
import ctypes, ctypes.wintypes as w, subprocess, sys, time, struct

out, delay, dur = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
k = ctypes.WinDLL('kernel32', use_last_error=True); psapi = ctypes.WinDLL('psapi')
k.OpenProcess.restype = w.HANDLE

class PMC(ctypes.Structure):
    _fields_ = [('cb', w.DWORD), ('PageFaultCount', w.DWORD)] + [(n, ctypes.c_size_t) for n in (
        'PeakWorkingSetSize', 'WorkingSetSize', 'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage',
        'QuotaPeakNonPagedPoolUsage', 'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage', 'PrivateUsage')]

def pids():
    res = {}
    for line in subprocess.run(['tasklist', '/FO', 'CSV', '/NH'], capture_output=True, text=True).stdout.splitlines():
        p = line.strip('"').split('","')
        if len(p) > 1 and p[0].lower() in ('bombd.exe', 'rebroadcasterlan.exe', 'nfs.exe'):
            res[p[0].lower()] = int(p[1])
    return res

def private_mb(pid):
    h = k.OpenProcess(0x1000 | 0x0010, False, pid)   # QUERY_LIMITED_INFORMATION | VM_READ
    if not h: return None, None
    c = PMC(); c.cb = ctypes.sizeof(PMC)
    psapi.GetProcessMemoryInfo(h, ctypes.byref(c), c.cb)
    return h, c.PrivateUsage / 2**20

time.sleep(delay)
end = time.time() + dur * 60
with open(out, 'a', buffering=1) as f:
    f.write('time      bombd_MB  rebroad_MB  nfs_MB  game_state\n')
    while time.time() < end:
        p = pids(); vals = {}; state = '-'
        for name in ('bombd.exe', 'rebroadcasterlan.exe', 'nfs.exe'):
            if name in p:
                h, mb = private_mb(p[name]); vals[name] = mb
                if name == 'nfs.exe' and h:
                    b = ctypes.create_string_buffer(4); g = ctypes.c_size_t()
                    if k.ReadProcessMemory(h, ctypes.c_void_p(0xABB510), b, 4, ctypes.byref(g)):
                        state = 'RACING' if struct.unpack('<i', b.raw)[0] == 6 else str(struct.unpack('<i', b.raw)[0])
                if h: k.CloseHandle(h)
        fmt = lambda v: f'{v:8.1f}' if v is not None else '       -'
        f.write(f"{time.strftime('%H:%M:%S')}  {fmt(vals.get('bombd.exe'))}  {fmt(vals.get('rebroadcasterlan.exe'))}  "
                f"{fmt(vals.get('nfs.exe'))}  {state}\n")
        time.sleep(10)
