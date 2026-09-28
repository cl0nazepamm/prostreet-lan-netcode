"""Tiny x86 PE helper: string xrefs, capstone disassembly with import/string annotations."""
import sys, struct
import pefile, capstone
class Bin:
    def __init__(s, path):
        s.pe = pefile.PE(path); s.base = s.pe.OPTIONAL_HEADER.ImageBase
        s.img = s.pe.get_memory_mapped_image()
        s.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); s.md.detail = False
        t = [x for x in s.pe.sections if x.Name.startswith(b'.text')][0]
        s.tstart = s.base + t.VirtualAddress; s.tend = s.tstart + t.Misc_VirtualSize
        s.imports = {}
        for e in getattr(s.pe,'DIRECTORY_ENTRY_IMPORT',[]):
            for i in e.imports:
                s.imports[i.address] = f"{e.dll.decode()}!{i.name.decode() if i.name else i.ordinal}"
    def rd(s, va, n): return s.img[va-s.base: va-s.base+n]
    def xrefs(s, target):
        pat = struct.pack('<I', target); out=[]; b = s.img; i = b.find(pat)
        while i!=-1:
            va = s.base+i
            if s.tstart <= va < s.tend: out.append(va)
            i = b.find(pat, i+1)
        return out
    def cstr(s, va):
        try:
            d = s.rd(va, 200); return d.split(b'\0')[0].decode('latin1')
        except Exception: return None
    def dis(s, va, n=60):
        code = s.rd(va, n*8); lines=[]
        for ins in s.md.disasm(code, va):
            ann=""
            for tok in ins.op_str.replace('[',' ').replace(']',' ').replace(',',' ').split():
                if tok.startswith('0x'):
                    v=int(tok,16)
                    if v in s.imports: ann+=" ; "+s.imports[v]
                    elif s.base+0x8f000 <= v < s.base+0xb6000:
                        c=s.cstr(v)
                        if c and len(c)>=3 and all(32<=ord(ch)<127 or ch in '\n\r\t' for ch in c): ann+=f' ; "{c[:90]}"'
            lines.append(f"{ins.address:08x}: {ins.mnemonic:6} {ins.op_str}{ann}")
            if len(lines)>=n: break
        return "\n".join(lines)
    def funcstart(s, va, maxback=0x3000):
        # heuristic: find preceding int3/ret padding boundary then push ebp or sub esp
        b = s.img; off = va - s.base
        for k in range(off, off-maxback, -1):
            if b[k-1] in (0xcc,0xc3,0x90) and (b[k:k+3]==b'\x55\x8b\xec' or b[k] in (0x83,0x81,0x6a,0x55,0x53,0x56,0x57,0x51,0x8b,0x64,0xa1,0x68,0xb8)):
                if b[k-1]==0xcc or (b[k-1]==0xc3 and b[k-2] in (0xcc,0x5d,0x5e,0x5f,0x5b,0xc9) ) or b[k-1]==0x90:
                    return s.base+k
        return None
