"""Loopback UDP proxy: client -> 127.0.0.1:LISTEN -> 127.0.0.1:UPSTREAM, logging every datagram.
Usage: python udpproxy.py LISTEN UPSTREAM SECONDS LOGFILE
Log line: t_ms dir len hex   (dir: C2S = client->server, S2C = server->client)
"""
import socket, sys, time, select

listen, upstream, secs, logf = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); front.bind(('127.0.0.1', listen))
back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); back.bind(('127.0.0.1', 0))
back.connect(('127.0.0.1', upstream))
client = None
t0 = time.perf_counter()
end = t0 + secs
with open(logf, 'w') as log:
    while time.perf_counter() < end:
        r, _, _ = select.select([front, back], [], [], 0.05)
        for s in r:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                continue
            t = (time.perf_counter() - t0) * 1000
            if s is front:
                client = addr; back.send(data); d = 'C2S'
            else:
                if client: front.sendto(data, client)
                d = 'S2C'
            log.write(f'{t:.3f} {d} {len(data)} {data.hex()}\n')
