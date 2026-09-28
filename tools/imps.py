"""Print sections and imports of a PE file. Usage: python imps.py FILE.exe"""
import sys
import pefile
pe = pefile.PE(sys.argv[1])
print("ImageBase", hex(pe.OPTIONAL_HEADER.ImageBase), "EP", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "TimeDateStamp", pe.FILE_HEADER.TimeDateStamp)
for s in pe.sections: print(s.Name.rstrip(b'\0'), hex(s.VirtualAddress), hex(s.Misc_VirtualSize), hex(s.PointerToRawData), hex(s.SizeOfRawData))
for e in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]):
    print(e.dll.decode(), ", ".join((i.name or str(i.ordinal).encode()).decode() if i.name else f"ord{i.ordinal}" for i in e.imports))
