"""nfs.exe analysis helper: loads the exe (PROSTREET_DIR) and caches a direct-call index."""
import sys, struct, os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rehelp, pickle
GAME_DIR = os.environ.get('PROSTREET_DIR', 'E:/Need for Speed ProStreet')
b = rehelp.Bin(os.path.join(GAME_DIR, 'nfs.exe'))
_cache = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nfs_calls.pkl')
def build_calls():
    if os.path.exists(_cache): return pickle.load(open(_cache,'rb'))
    img=b.img; lo=0x1000; hi=0x567000-5; m={}
    i=img.find(b'\xE8', lo)
    while 0<=i<hi:
        t=b.base+i+5+struct.unpack('<i', img[i+1:i+5])[0]
        if b.tstart<=t<b.tend: m.setdefault(t,[]).append(b.base+i)
        i=img.find(b'\xE8', i+1)
    pickle.dump(m, open(_cache,'wb')); return m
CALLS = build_calls()
def fstart(va):
    k=va
    while k>b.tstart:
        if b.img[k-b.base-1]==0xCC and b.img[k-b.base-2]==0xCC: return k
        k-=1
def callers(t): return CALLS.get(t,[])
