#!/usr/bin/env python3
"""Pure-python pcap latency attribution for rpc-fabric-tracer traffic. No root, no deps.

Reassembles each TCP direction (by sequence number), parses length-prefixed RPC frames,
pairs request/response by request id, and splits end-to-end latency using capture
timestamps plus the server timestamps embedded in every response:

  total      = response capture ts - request capture ts
  queueing   = server_recv_ns - request capture ts   (wire to server + kernel + server queue, client-side view)
  server     = server_send_ns - server_recv_ns       (time inside the server process)
  wire/kernel return = response capture ts - server_send_ns
"""
import json, struct, sys
from collections import defaultdict

HEADER_LEN = 36

def read_pcap(path):
    data = open(path, 'rb').read()
    if len(data) < 24: raise ValueError('short pcap')
    magic = data[:4]
    if magic == b'\xd4\xc3\xb2\xa1': end = '<'
    elif magic == b'\xa1\xb2\xc3\xd4': end = '>'
    else: raise ValueError('not a pcap (bad magic)')
    linktype = struct.unpack(end + 'I', data[20:24])[0]
    off, packets = 24, []
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, _ = struct.unpack(end + 'IIII', data[off:off+16]); off += 16
        packets.append((ts_sec + ts_usec / 1e6, data[off:off+incl])); off += incl
    return linktype, packets

def parse_tcp(linktype, pkt):
    """Return (flow_key, direction_key, seq, payload) or None. flow is unordered, direction is src->dst."""
    if linktype == 1:  # Ethernet
        if len(pkt) < 14 or pkt[12:14] != b'\x08\x00': return None
        pkt = pkt[14:]
    elif linktype in (0, 101):  # BSD loopback / raw IP: skip 4-byte family header if present
        if len(pkt) >= 4 and pkt[0] >> 4 != 4: pkt = pkt[4:]
    if len(pkt) < 20 or pkt[0] >> 4 != 4 or pkt[9] != 6: return None
    ihl = (pkt[0] & 0xF) * 4
    src, dst = pkt[12:16], pkt[16:20]
    tcp = pkt[ihl:]
    if len(tcp) < 20: return None
    sport, dport = struct.unpack('>HH', tcp[:4])
    seq = struct.unpack('>I', tcp[4:8])[0]
    doff = (tcp[12] >> 4) * 4
    payload = tcp[doff:]
    if not payload: return None
    a, b = (src, sport), (dst, dport)
    return (frozenset((a, b)), (a, b), seq, payload)

def reassemble(segments):
    segments.sort(key=lambda s: s[0])
    out, expect = bytearray(), None
    for seq, payload in segments:
        if expect is None: expect = seq
        if seq > expect: break  # ponytail: gap = truncated capture; stop rather than guess
        skip = expect - seq
        if skip < len(payload): out += payload[skip:]; expect += len(payload) - skip
    return bytes(out)

def parse_frames(buf, capture_ts):
    """Yield (id, type, client_send_ns, server_recv_ns, server_send_ns). capture_ts per frame is approximate:
    the analyzer attributes a frame to the timestamp of the stream (see analyze())."""
    off = 0
    while off + 4 + HEADER_LEN <= len(buf):
        (length,) = struct.unpack('>I', buf[off:off+4])
        if length < HEADER_LEN or off + 4 + length > len(buf): break
        h = buf[off+4:off+4+HEADER_LEN]
        rid, = struct.unpack('>Q', h[:8])
        yield rid, h[8], *struct.unpack('>QQQ', h[12:36])
        off += 4 + length

def analyze(path):
    linktype, packets = read_pcap(path)
    # Per-direction: keep (capture_ts, seq, payload); a frame's capture time is the ts of
    # the packet that completes it — approximated here by latest segment ts in that direction
    # up to the frame end. Simple approach: track frames incrementally per direction.
    streams, pending = {}, {}  # direction -> [bytearray, next_frame_start_offset, records]
    results = {}
    for ts, pkt in packets:
        parsed = parse_tcp(linktype, pkt)
        if not parsed: continue
        _, direction, seq, payload = parsed
        st = streams.setdefault(direction, {'segs': [], 'buf': b'', 'frames': [], 'ts_of_byte': []})
        st['segs'].append((seq, payload, ts))
        st['segs'].sort(key=lambda s: s[0])
        buf = reassemble([(s, p) for s, p, _ in st['segs']])
        if len(buf) <= len(st['buf']): continue
        # timestamp for new bytes: ts of the segment that provided the tail
        new_frames = list(parse_frames(buf, ts))
        for rec in new_frames[len(st['frames']):]:
            st['frames'].append((ts, rec))
        st['buf'] = buf
    reqs, resps = {}, {}
    for direction, st in streams.items():
        for ts, (rid, typ, c_send, s_recv, s_send) in st['frames']:
            (reqs if typ == 0 else resps)[rid] = (ts, c_send, s_recv, s_send)
    rows = []
    for rid in sorted(set(reqs) & set(resps)):
        req_ts, _, _, _ = reqs[rid]; resp_ts, _, s_recv, s_send = resps[rid]
        total_us = (resp_ts - req_ts) * 1e6
        server_us = (s_send - s_recv) / 1e3 if s_send and s_recv else 0.0
        queue_us = (s_recv / 1e9 - req_ts) * 1e6 if s_recv else 0.0
        ret_us = (resp_ts - s_send / 1e9) * 1e6 if s_send else 0.0
        rows.append({'id': rid, 'total_us': round(total_us, 2), 'queueing_us': round(queue_us, 2),
                     'server_us': round(server_us, 2), 'wire_kernel_return_us': round(ret_us, 2)})
    return rows

def pct(vals, p):
    if not vals: return 0.0
    vals = sorted(vals); return vals[min(len(vals)-1, int(p*len(vals)))]

def main(argv):
    rows = analyze(argv[1])
    if '--json' in argv:
        print(json.dumps(rows, indent=2)); return 0
    print(f"paired_requests={len(rows)}")
    for key in ('total_us', 'queueing_us', 'server_us', 'wire_kernel_return_us'):
        vals = [r[key] for r in rows]
        print(f"{key}: p50={pct(vals,.5):.1f} p99={pct(vals,.99):.1f} max={max(vals) if vals else 0:.1f} (us)")
    for r in rows[:10]: print(r)
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
