# NFS ProStreet LAN netcode fixes

Reverse engineering and binary patches for **Need for Speed ProStreet**'s PC LAN mode (EA's December 2007
LAN patch: `nfs.exe` v1.1 + the `ONLINE\` LAN server) so it works, and plays well, on Windows 10/11 —
including over Tailscale.

No game binaries are included. The patchers only modify files you already have, and each one verifies the
exact original bytes at every site before writing anything.

## What was wrong, and what the patches do

| # | Where | Problem | Fix | Result (measured) |
|---|---|---|---|---|
| 1 | `rebroadcasterlan.exe` | Creates its UDP socket with `socket(AF_UNSPEC, SOCK_DGRAM, UDP)`. On modern Windows the Winsock catalog lists UDP/IPv6 first, so it gets an IPv6 socket, `connect()` to `127.0.0.1` fails (WSAEFAULT) and it exits with `CouldNotInitializeDataConnection`. The server can't host a single race. | Force `AF_INET` for the socket and the `getaddrinfo` hints (tiny code cave). | Race server starts, logs into bombd, creates its game. |
| 2 | `bombd.exe`, `rebroadcasterlan.exe` | Main loops idle with `Sleep(10)` and never raise timer resolution, so every tick is ~15.6 ms. Every relayed message waits for ticks. | Entry-point stub: `SetProcessInformation` (Windows 11 must honor timer resolution for windowless processes) + `timeBeginPeriod(1)`; main-loop `Sleep(10)` → `Sleep(1)`. | bombd reply: mean 9.6 → **1.6 ms**, max 17.3 → 4.0 ms. Rebroadcaster reaction: mean 15.1 → **2.0 ms**, max 24 → 2.5 ms. |
| 3 | `nfs.exe` | In LAN races the main loop takes its frame `dt` from a network clock built on `GetTickCount()`, which only advances every 15.625 ms. At high FPS most frames get `dt = 0`, then a 16 ms jump: physics runs in bursts and your **own car judders** (solo races use QPC and are smooth). | The 11 `GetTickCount` reads that make up that clock (all relative to the shared base at `0xB30800`) now read `timeGetTime()` — same signature, 1 ms resolution (the game already calls `timeBeginPeriod(1)`). IAT operand swaps only. | Sim ticks arriving after a >2× gap: **7.9 % → 0 %**; p99 gap 16.3 → 5.1 ms. |
| 4 | `nfs.exe` | Each client sends `OLMSG_CarState` for its cars (player + any AI it hosts) at **15 Hz**; opponents are extrapolated for ~66 ms + latency between updates. | The send scheduler's `fadd qword [0x9713D8]` (a 1/15 constant shared with unrelated code) is pointed at a private double in unused `int3` padding at `0x7C2338`. Default **60 Hz**; 15/20/30/40/60 selectable. | Stock 15 Hz confirmed on the wire (see protocol notes). 60 Hz: opponents visibly tighter; not yet measured on the wire. |

FusionFix (`NFSProStreet.FusionFix.asi`, `Win11LANFix = 1`) already fixes the same `AF_UNSPEC` bug in the
**client**; see xan1242's [WidescreenFixesPack PR #1336](https://github.com/ThirteenAG/WidescreenFixesPack/pull/1336),
which also notes the rebroadcaster needs it. None of the patches here overlap FusionFix's byte patterns.

## Known issue: memory leak (TODO)

bombd, the rebroadcaster and the game all grow by a fixed amount per car-state message and never free it,
even after the race ends (measured with `tools/memlog.py`, 60 Hz, 2 players + AI):

| process | growth while racing |
|---|---|
| `bombd.exe` | ~52 MB/min |
| `rebroadcasterlan.exe` | ~34 MB/min |
| `nfs.exe` | ~20 MB/min |

None of the exes is large-address-aware, so they die at ~2 GB. The bombd : rebroadcaster ratio (≈3 : 2)
matches unreliable packets *sent*, which points at the shared netcode library keeping a per-send record
(bombd has an `AckPacketRecord` allocation tag) that is never released because unreliable packets are never
acked — unverified. It exists in the stock game too; 15 Hz just made it slow. Workaround: **File → Restart**
in the LAN Server window between sessions (and restart the game now and then), or use `-Rate 30`.

## Applying

Requirements for the Python patchers/tools: Python 3 (32-bit not needed), `pip install -r requirements.txt`
(`nfs_lan_patch.py` and the `.ps1` have no dependencies).

**LAN server** (only on the PC that runs the server; close the LAN Server window first):

```
python patches/server_patcher.py rebroadcaster ORIG/rebroadcasterlan.exe ONLINE/rebroadcasterlan.exe --sleep 1
python patches/server_patcher.py bombd        ORIG/bombd.exe            ONLINE/bombd.exe            --sleep 1
```

**Game client** (every player; game closed):

```
python patches/nfs_lan_patch.py ORIG/nfs.exe GAME/nfs.exe [--rate 60]
# or, no Python needed — put the script next to nfs.exe:
powershell -ExecutionPolicy Bypass -File .\ProStreet-LAN-fix.ps1 [-Rate 60]
```

Keep the originals; the PowerShell script keeps the first `nfs.exe.before-lanfix` backup. `--rate 15` /
`-Rate 15` restores the stock send rate (byte-identical to the clock-fix-only exe).

**Settings:** both players should use the same FusionFix `SimRate` if remote cars look off
(we run `-1` on a 240 Hz and a 144 Hz monitor and it's fine after fixes 3 + 4).

### Hashes (MD5)

| file | original | patched |
|---|---|---|
| `nfs.exe` | `06e4237e74ccd8cd6625b19058ca1e96` | 60 Hz `ebc5ca028929e999a3be9174307a4241` · 30 Hz `ec3bb555ee4c46ee66e7c3dd9cc48cab` · clock only `e2277549a61a35dc30fa7d581edeecb2` |
| `bombd.exe` | `bc49ce807cd58f35177c526be2247f77` | `28be0582b0c9f53eea65a7a62a5d0c5a` |
| `rebroadcasterlan.exe` | `bb4b9c7e58fbd7ad8d395c7e179f4542` | `7e6eafbaad18a4cca7a62269b29618f6` |

## Playing over Tailscale

Everything goes through the server (players never connect to each other), so only the host's
UDP `10104` needs to be reachable; sharing the host machine to friends is enough. Tailscale doesn't carry
broadcasts, so LAN auto-discovery won't find the server: let it time out and enter the host's Tailscale IP and
port `10104` on the IP/Port screen. `tailscale ping <host>` should say `via <ip>:<port>` (direct), not
`via DERP(...)`.

## Architecture / protocol notes

* `launcher.exe` (.NET) starts `bombd.exe -port 10104 -httpport 8080` and `MaxGameInstances` ×
  `rebroadcasterlan.exe -gamename game_N -lanport 10104` (settings in
  `HKCU\Software\Electronic Arts\Need for Speed ProStreet\LAN Launcher`).
* **bombd** = lobby/accounts/stats + relay. UDP `10104` (data, `-port`), UDP `10105` (discovery, hard-coded),
  TCP `8080` (stats web/RSS). Player DB `playerDB.txt`, stats `statsdb.bin`.
* **rebroadcaster** = one game host per slot. Connects to bombd on `127.0.0.1:<lanport>`, logs in as
  `pclan/pclan`, `createGame`, `publishAttributes` (`__JOINMODE=CLOSED` until claimed). Assigns AI cars to a
  client to simulate ("Car '%i' now hosted by '%s'").
* Race traffic: client → bombd → rebroadcaster → bombd → every client (the sender gets its own echo).
* Reliable-UDP packet header `[type:1][flag:1][msgno:u16][seq:u32 LE]`: `a` keepalive/ping (GetTickCount
  timestamp, bytes 1–3 uninitialized), `b` handshake, `c` ack (`cb` handshake, `cd` data), `d` reliable data
  (XML: `<service name="connect|login|gamemanager|gamebrowser|stats">…`), `e` unreliable game datagram,
  `f` (seen in races, not decoded).
* `e` game datagram: `65 <slot> fe ff <seq u32> 00000000 <OLMSG type> 000000 <car id>` + quantized state;
  the rebroadcaster re-sends as `65 fe <dest slot> 00 …`. `OLMSGType_CarState` = `0x16`, player cars
  `0x64`, `0x65`, …; 50 bytes each.
* `nfs.exe` main loop `0x6DAD70`: `if (*(bool*)0xB307FE) dt = netclock_delta()  /* 0x7B2BA0 */ else dt =
  QPC frame time`. Car-state scheduler in `0x7C1190`: resync if `|now − next| > 1/15`, send when
  `next <= now`, `next += INTERVAL`.

## Tools (`tools/`)

Set `PROSTREET_DIR` if the game isn't in `E:\Need for Speed ProStreet`.

| tool | what it does |
|---|---|
| `rehelp.py`, `nfsre.py` | capstone/pefile helpers: string xrefs, annotated disassembly, call index for `nfs.exe` |
| `strs.py`, `imps.py` | strings (ASCII + UTF-16) and imports/sections of a PE |
| `probe.py` | fake client for bombd's reliable-UDP protocol; measures request→reply latency (`listGames`) |
| `udpproxy.py` | logging loopback UDP proxy (put it between the rebroadcaster and bombd via `-lanport`) |
| `rbtap.py` | same idea, used to capture a whole race between rebroadcaster and bombd |
| `kaecho.py` | keepalive-echo timing (note: dropping pings perturbs the protocol; results were confounded) |
| `racemon.py` | profiles `nfs.exe` during solo vs LAN races: frame-pacing counters + main-thread stack sampling |
| `memscan.py` | finds per-frame counters in `nfs.exe` memory |
| `memlog.py` | logs bombd / rebroadcaster / nfs private memory every 10 s |
