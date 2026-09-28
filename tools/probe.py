"""Fake ProStreet LAN client: measures bombd request->reply latency over its reliable-UDP protocol.
Packet: [type:1][flag:1][msgno:u16][seq:u32 LE] + payload.  b=handshake  c=ack  d=data  a=keepalive
Usage: python probe.py PORT N_REQUESTS OUT_JSON [join GAMENAME]
"""
import socket, struct, sys, time, random, json, os

port, n, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('127.0.0.1', port))
s.settimeout(2.0)
seq = random.getrandbits(31)
msgno = 0

def xml(service, txn, method, params=()):
    p = ''.join(f'<param><name> {k} </name><value> {v} </value></param>' for k, v in params)
    return (f'<service name="{service}"><transaction id="{txn}" type="TRANSACTION_TYPE_REQUEST">'
            f'<method> {method}{p}</method></transaction></service>\0').encode()

TRACE = []
def recv_data(txn):
    """Return the server reply for transaction txn, acking every data packet."""
    tag = f'transaction id="{txn}"'.encode()
    while True:
        pkt = s.recv(65535)
        TRACE.append((time.perf_counter(), pkt[:8].hex(), pkt[8:90]))
        if pkt[0] == 0x64:
            s.send(b'cd\xa0\x0f' + pkt[4:8])
            if tag in pkt[8:]:
                return pkt[8:]

def request(service, method, params=()):
    global seq, msgno
    seq = (seq + 1) & 0xFFFFFFFF
    body = xml(service, msgno, method, params)
    pkt = b'd\x01' + struct.pack('<HI', msgno & 0xFFFF, seq) + body
    msgno += 1
    t = time.perf_counter()
    s.send(pkt)
    reply = recv_data(msgno - 1)
    return (time.perf_counter() - t) * 1000, reply

# handshake
s.send(b'bs' + os.urandom(2) + struct.pack('<II', seq, seq))
got_ack = got_syn = False
while not (got_ack and got_syn):
    pkt = s.recv(65535)
    if pkt[:2] == b'cb': got_ack = True
    elif pkt[0] == 0x62:
        got_syn = True
        s.send(b'cb\x66\x01' + pkt[4:8])

user = f'probe{random.randrange(10**6)}'
setup = [request('connect', 'startConnect'),
         request('login', 'addUser', [('password', 'x'), ('username', user)]),
         request('login', 'startLogin', [('password', 'x'), ('username', user)])]
lat = []
mode = sys.argv[4] if len(sys.argv) > 4 else 'list'
for i in range(n):
    time.sleep(random.uniform(0, 0.02))          # random phase vs. the server tick
    if mode == 'join':
        ms, reply = request('gamemanager', 'joinGame', [('gamename', sys.argv[5])])
        if i == 0: print('JOIN REPLY:', reply[:300].decode('latin1'))
        time.sleep(random.uniform(0.05, 0.1))
        request('gamemanager', 'leaveGame', [('gamename', sys.argv[5])])
    else:
        ms, reply = request('gamebrowser', 'listGames')
    lat.append(ms)
lat.sort()
res = {'n': n, 'setup_ms': [round(x[0], 2) for x in setup],
       'first_reply': setup[2][1][:160].decode('latin1'),
       'last_reply': reply[:200].decode('latin1'),
       'min': lat[0], 'p50': lat[n // 2], 'mean': sum(lat) / n, 'p95': lat[int(n * .95)],
       'p99': lat[int(n * .99)], 'max': lat[-1]}
res['trace_head'] = [(round((t-TRACE[0][0])*1000,2), h, p.decode('latin1')) for t,h,p in TRACE[:24]]
json.dump(res, open(out, 'w'), indent=1)
print(json.dumps({k: (round(v, 2) if isinstance(v, float) else v) for k, v in res.items() if k != 'trace_head'}, indent=1))
