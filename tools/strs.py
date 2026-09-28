import sys, re
data = open(sys.argv[1],'rb').read()
mn = int(sys.argv[2]) if len(sys.argv)>2 else 5
for m in re.finditer(rb'[\x20-\x7e]{%d,}' % mn, data):
    print(hex(m.start()), m.group().decode())
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){%d,}' % mn, data):
    print(hex(m.start()), 'W', m.group().decode('utf-16le'))
