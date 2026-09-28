"""Tap between rebroadcasterlan.exe and bombd: forwards UDP both ways on loopback and logs every datagram
(time, direction, length, first 64 bytes). RB2B = rebroadcaster->bombd, B2RB = bombd->rebroadcaster.
Usage: python rbtap.py LISTEN_PORT BOMBD_PORT SECONDS LOGFILE
"""
import socket, sys, time, select

listen, upstream, secs, logf = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); front.bind(('127.0.0.1', listen))
back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); back.bind(('127.0.0.1', 0))
back.connect(('127.0.0.1', upstream))
client = None
t0 = time.perf_counter(); end = t0 + secs
with open(logf, 'w', buffering=1 << 16) as log:
    while time.perf_counter() < end:
        r, _, _ = select.select([front, back], [], [], 0.05)
        for s in r:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                continue
            t = (time.perf_counter() - t0) * 1000
            if s is front:
                client = addr; back.send(data); d = 'RB2B'
            else:
                if client: front.sendto(data, client)
                d = 'B2RB'
            log.write(f'{t:.3f} {d} {len(data)} {data[:64].hex()}\n')
