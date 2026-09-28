"""Race monitor for nfs.exe: when the player is racing, profile the game once in SOLO mode and once in
LAN mode (LAN = nfs.exe has a UDP socket connected to port 10104), then write a comparison.

Per mode it records:
  * frame pacing: finds per-frame counters in .data (steady 30..500/s), then polls them at ~1 kHz
  * where the busiest (main) thread spends time: suspend/read EIP+stack/resume every ~2 ms, attributing each
    sample to the module EIP is in and the first nfs.exe caller (plus the import it called, e.g. Sleep)
Read-only apart from briefly suspending one thread for each stack sample.
Usage: python racemon.py OUT_DIR [MAX_MINUTES]
"""
import ctypes, ctypes.wintypes as w, time, sys, struct, subprocess, json, array, collections, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rehelp

OUT = sys.argv[1]; MAXMIN = float(sys.argv[2]) if len(sys.argv) > 2 else 40
MODES = sys.argv[3].split(',') if len(sys.argv) > 3 else ['SOLO', 'LAN']
REPEAT = len(sys.argv) > 4 and sys.argv[4] == 'repeat'   # keep capturing timestamped profiles
os.makedirs(OUT, exist_ok=True)
LOG = open(os.path.join(OUT, 'racemon.log'), 'a', buffering=1)
def log(*a):
    LOG.write(time.strftime('%H:%M:%S ') + ' '.join(str(x) for x in a) + '\n')

k = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)
k.OpenProcess.restype = w.HANDLE; k.OpenThread.restype = w.HANDLE
k.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k.CreateToolhelp32Snapshot.restype = w.HANDLE
k.SuspendThread.restype = w.DWORD; k.ResumeThread.restype = w.DWORD

GAME = rehelp.Bin(os.path.join(os.environ.get('PROSTREET_DIR', 'E:/Need for Speed ProStreet'), 'nfs.exe'))
TEXT_LO, TEXT_HI = 0x401000, 0x967000
STATE_ADDR, RACING = 0xABB510, 6          # gameflow state; the in-race frame limiter runs when it == 6
DATA_LO, DATA_HI = 0x64A000, 0x64A000 + 0x5C6000

def game_pid():
    out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq nfs.exe', '/FO', 'CSV', '/NH'], capture_output=True, text=True).stdout
    return int(out.split('","')[1]) if 'nfs.exe' in out else None

class Proc:
    def __init__(self, pid):
        self.pid = pid
        self.h = k.OpenProcess(0x0410, False, pid)
        self.modules = self._modules()
    def rd(self, a, n):
        b = ctypes.create_string_buffer(n); g = ctypes.c_size_t()
        return b.raw[:g.value] if k.ReadProcessMemory(self.h, ctypes.c_void_p(a), b, n, ctypes.byref(g)) else b''
    def u32(self, a):
        r = self.rd(a, 4); return struct.unpack('<I', r)[0] if len(r) == 4 else None
    def _modules(self):
        arr = (w.HMODULE * 1024)(); need = w.DWORD()
        psapi.EnumProcessModulesEx(self.h, arr, ctypes.sizeof(arr), ctypes.byref(need), 1)  # LIST_MODULES_32BIT
        mods = []
        class MI(ctypes.Structure): _fields_ = [('base', ctypes.c_void_p), ('size', w.DWORD), ('ep', ctypes.c_void_p)]
        for hm in arr[:need.value // ctypes.sizeof(w.HMODULE)]:
            if not hm: continue
            mi = MI(); psapi.GetModuleInformation(self.h, ctypes.c_void_p(hm), ctypes.byref(mi), ctypes.sizeof(mi))
            nm = ctypes.create_unicode_buffer(260); psapi.GetModuleBaseNameW(self.h, ctypes.c_void_p(hm), nm, 260)
            mods.append((mi.base or 0, mi.size, nm.value))
        return mods
    def module_of(self, a):
        for base, size, nm in self.modules:
            if base <= a < base + size: return nm
        return '?'
    def lan(self):
        out = subprocess.run(['netstat', '-ano', '-p', 'UDP'], capture_output=True, text=True).stdout
        return any(l.split()[-1] == str(self.pid) and ':10104' in l.split()[2] for l in out.splitlines() if len(l.split()) >= 4)
    def threads(self):
        class TE(ctypes.Structure):
            _fields_ = [('dwSize', w.DWORD), ('cntUsage', w.DWORD), ('th32ThreadID', w.DWORD), ('th32OwnerProcessID', w.DWORD),
                        ('tpBasePri', ctypes.c_long), ('tpDeltaPri', ctypes.c_long), ('dwFlags', w.DWORD)]
        snap = k.CreateToolhelp32Snapshot(4, 0); te = TE(); te.dwSize = ctypes.sizeof(TE); ids = []
        ok = k.Thread32First(snap, ctypes.byref(te))
        while ok:
            if te.th32OwnerProcessID == self.pid: ids.append(te.th32ThreadID)
            ok = k.Thread32Next(snap, ctypes.byref(te))
        k.CloseHandle(snap); return ids

def thread_cpu(tid):
    th = k.OpenThread(0x0040 | 0x0800, False, tid)   # QUERY_INFORMATION | QUERY_LIMITED
    if not th: return 0
    c, e, kt, ut = w.FILETIME(), w.FILETIME(), w.FILETIME(), w.FILETIME()
    k.GetThreadTimes(th, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut)); k.CloseHandle(th)
    return ((kt.dwHighDateTime << 32 | kt.dwLowDateTime) + (ut.dwHighDateTime << 32 | ut.dwLowDateTime)) / 1e4  # ms

def busiest_thread(p, secs=1.0):
    ids = p.threads(); a = {t: thread_cpu(t) for t in ids}; time.sleep(secs); b = {t: thread_cpu(t) for t in ids}
    ranked = sorted(ids, key=lambda t: b[t] - a[t], reverse=True)
    return ranked, {t: round((b[t] - a[t]) / secs / 10, 1) for t in ranked[:6]}   # % of one core

def is_call_ret(v):
    """True if v looks like a return address in nfs.exe .text (instruction before it is a call)."""
    if not (TEXT_LO <= v < TEXT_HI): return None
    by = GAME.rd(v - 7, 7)
    if by[2] == 0xE8: return ('rel', v + struct.unpack('<i', by[3:7])[0])
    if by[1] == 0xFF and by[2] == 0x15:
        iat = struct.unpack('<I', by[3:7])[0]; return ('imp', GAME.imports.get(iat, hex(iat)))
    if by[5] == 0xFF and 0xD0 <= by[6] <= 0xD7: return ('reg', None)
    if by[4] == 0xFF and 0x50 <= by[5] <= 0x57: return ('vt', None)
    if by[1] == 0xFF and 0x90 <= by[2] <= 0x97: return ('vt', None)
    return None

_fcache = {}
def func_of(va):
    if va in _fcache: return _fcache[va]
    kk = va
    while kk > TEXT_LO and not (GAME.img[kk - GAME.base - 1] == 0xCC and GAME.img[kk - GAME.base - 2] == 0xCC): kk -= 1
    _fcache[va] = kk; return kk

class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [('raw', ctypes.c_ubyte * 0x2CC)]

def stack_profile(p, tid, secs):
    th = k.OpenThread(0x0002 | 0x0008 | 0x0040, False, tid)  # SUSPEND_RESUME | GET_CONTEXT | QUERY_INFORMATION
    ctx = WOW64_CONTEXT(); mods = collections.Counter(); callers = collections.Counter(); n = 0
    end = time.perf_counter() + secs
    while time.perf_counter() < end:
        struct.pack_into('<I', ctx.raw, 0, 0x00010001)   # WOW64_CONTEXT_CONTROL
        if k.SuspendThread(th) == 0xFFFFFFFF: break
        ok = k.Wow64GetThreadContext(th, ctypes.byref(ctx))
        eip, esp = struct.unpack_from('<I', ctx.raw, 0xB8)[0], struct.unpack_from('<I', ctx.raw, 0xC4)[0]
        stack = p.rd(esp, 0x800) if ok else b''
        k.ResumeThread(th)
        if not ok: continue
        n += 1
        mod = p.module_of(eip); mods[mod] += 1
        if TEXT_LO <= eip < TEXT_HI:
            callers[(f'{func_of(eip):#x}', 'running')] += 1
        else:
            site = None
            for i in range(0, len(stack) - 3, 4):
                v = struct.unpack_from('<I', stack, i)[0]; r = is_call_ret(v)
                if r:
                    site = (f'{func_of(v):#x}', f'{mod} via ' + (r[1] if r[0] == 'imp' else (f'call {r[1]:#x}' if r[0] == 'rel' else r[0])))
                    break
            callers[site or ('?', mod)] += 1
        time.sleep(0.002)
    k.CloseHandle(th)
    return n, mods, callers

def frame_pacing(p):
    def snap():
        arr = array.array('I'); raw = bytearray()
        for a in range(DATA_LO, DATA_HI, 0x10000):
            chunk = p.rd(a, 0x10000); raw += chunk.ljust(0x10000, b'\0')
        arr.frombytes(bytes(raw)); return arr
    t0 = time.perf_counter(); s0 = snap(); time.sleep(1.5); t1 = time.perf_counter(); s1 = snap()
    cand = [i for i in range(len(s0)) if 30 <= (s1[i] - s0[i]) / (t1 - t0) <= 500]
    time.sleep(1.0); t2 = time.perf_counter(); s2 = snap()
    steady = []
    for i in cand:
        r1, r2 = (s1[i] - s0[i]) / (t1 - t0), (s2[i] - s1[i]) / (t2 - t1)
        if r2 > 0 and abs(r1 - r2) < 0.1 * max(r1, r2): steady.append((DATA_LO + 4 * i, round(r2, 1)))
    steady = steady[:12]
    # poll candidates ~1 kHz for 8 s, record time between increments
    last = {a: p.u32(a) for a, _ in steady}; lastt = {a: time.perf_counter() for a, _ in steady}; gaps = {a: [] for a, _ in steady}
    end = time.perf_counter() + 8
    while time.perf_counter() < end:
        now = time.perf_counter()
        for a, _ in steady:
            v = p.u32(a)
            if v is not None and v != last[a]:
                gaps[a].append((now - lastt[a]) * 1000 / max(1, (v - last[a]) & 0xFFFFFFFF))
                last[a] = v; lastt[a] = now
        time.sleep(0.0005)
    res = []
    for a, rate in steady:
        g = sorted(gaps[a])
        if len(g) > 20:
            res.append({'addr': hex(a), 'rate_per_s': rate, 'n': len(g), 'p50_ms': round(g[len(g) // 2], 2),
                        'p99_ms': round(g[int(len(g) * .99)], 2), 'max_ms': round(g[-1], 2),
                        'over_2x_p50_pct': round(100 * sum(x > 2 * g[len(g) // 2] for x in g) / len(g), 2)})
    return res

def main():
    done = {}; deadline = time.time() + MAXMIN * 60; p = None
    log('racemon started')
    while time.time() < deadline and (REPEAT or len(done) < len(MODES)):
        pid = game_pid()
        if not pid: time.sleep(3); continue
        if not p or p.pid != pid: p = Proc(pid); log('attached', pid, 'modules', len(p.modules))
        st = p.u32(STATE_ADDR)
        if st != getattr(main, 'last_state', None):
            log('gameflow state ->', st, '(lan)' if p.lan() else ''); main.last_state = st
        if st != RACING: time.sleep(2); continue
        mode = 'LAN' if p.lan() else 'SOLO'
        if (mode in done and not REPEAT) or mode not in MODES: time.sleep(3); continue
        log(mode, 'race detected, waiting 5 s for the race to settle'); time.sleep(5)
        if p.u32(STATE_ADDR) != RACING: continue
        simrate = round(1 / struct.unpack('<f', p.rd(0x9EE934, 4))[0], 1)
        ranked, cpu = busiest_thread(p)
        log(mode, 'busiest threads (% core):', cpu)
        pacing = frame_pacing(p)
        log(mode, 'frame pacing candidates:', len(pacing))
        n, mods, callers = stack_profile(p, ranked[0], 12)
        if p.u32(STATE_ADDR) != RACING:
            log(mode, 'left the race during measurement, will retry'); continue
        key = f"{mode}_{time.strftime('%H%M%S')}" if REPEAT else mode
        done[key] = {'simrate': simrate, 'thread_cpu_pct': cpu, 'main_tid': ranked[0], 'samples': n,
                      'modules_pct': {m: round(100 * c / n, 1) for m, c in mods.most_common(12)},
                      'top_sites_pct': [(f, s, round(100 * c / n, 1)) for (f, s), c in callers.most_common(25)],
                      'frame_pacing': pacing}
        json.dump(done, open(os.path.join(OUT, 'racemon.json'), 'w'), indent=1)
        log(key, 'profile saved')
        if REPEAT: time.sleep(20)
        try:
            import winsound; winsound.Beep(880, 150)
        except Exception: pass
    log('racemon finished with', list(done))

if __name__ == '__main__':
    main()
