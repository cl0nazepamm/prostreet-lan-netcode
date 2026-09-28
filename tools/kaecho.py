"""Loopback UDP proxy that measures how fast the client (rebroadcaster) echoes the server's (bombd's)
keepalive pings. Client-initiated pings are dropped so the server always starts the exchange.
Usage: python kaecho.py LISTEN UPSTREAM SECONDS OUT_JSON
"""
import socket, sys, time, select, json

listen, upstream, secs, out = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); front.bind(('127.0.0.1', listen))
back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); back.bind(('127.0.0.1', 0))
back.connect(('127.0.0.1', upstream))
client, created, dropped = None, False, 0
pending, lat = {}, []
end = time.perf_counter() + secs
while time.perf_counter() < end:
    r, _, _ = select.select([front, back], [], [], 0.05)
    for s in r:
        try:
            data, addr = s.recvfrom(65535)
        except OSError:
            continue
        t = time.perf_counter()
        is_ping = data[:1] == b'a' and len(data) == 8
        if s is front:
            client = addr
            if is_ping:
                key = data[4:8]
                if key in pending:
                    lat.append((t - pending.pop(key)) * 1000)
                else:
                    dropped += 1
                    continue                      # client-initiated ping: drop it
            back.send(data)
        else:
            if b'createGame </method>' in data: created = True
            if is_ping: pending[data[4:8]] = t
            if client: front.sendto(data, client)
lat.sort(); n = len(lat)
res = {'created': created, 'client_pings_dropped': dropped, 'samples': n}
if n:
    res.update(mean=sum(lat) / n, p50=lat[n // 2], p95=lat[int(n * .95)], max=lat[-1])
json.dump(res, open(out, 'w'), indent=1)
print(json.dumps({a: round(b, 2) if isinstance(b, float) else b for a, b in res.items()}))
