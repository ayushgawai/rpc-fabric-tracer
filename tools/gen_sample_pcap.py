#!/usr/bin/env python3
"""Generate a synthetic .pcap of rpc-fabric-tracer traffic (no root / no live capture needed).

Timestamps are fully deterministic: request at t, server_recv = t+40us,
server_send = +15us later, response captured +30us after that."""
import struct, sys

def ip_checksum(h):
    if len(h) % 2: h += b'\0'
    s = sum(struct.unpack('>%dH' % (len(h)//2), h)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

def packet(ts_us, src, dst, sport, dport, seq, payload):
    tcp = struct.pack('>HHIIHHHH', sport, dport, seq, 0, (5 << 12) | 0x18, 65535, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, total, 1, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
    eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    pkt = eth + ip + tcp + payload
    sec, usec = divmod(ts_us, 1_000_000)
    return struct.pack('<IIII', sec, usec, len(pkt), len(pkt)) + pkt

def frame(rid, typ, c_send_ns, s_recv_ns, s_send_ns, body=b'hello'):
    hdr = struct.pack('>QBBHHQQQ', rid, typ, 1, 0, 0, c_send_ns, s_recv_ns, s_send_ns)
    # layout must match rpc.hpp: id(8) type(1) op(1) flags(2) ts x3(24) = 36 bytes
    hdr = struct.pack('>Q', rid) + bytes([typ, 1, 0, 0]) + struct.pack('>QQQ', c_send_ns, s_recv_ns, s_send_ns)
    return struct.pack('>I', len(hdr) + len(body)) + hdr + body

def main(path='sample.pcap', n=10):
    out = [struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)]
    a, b = bytes([127,0,0,1]), bytes([127,0,0,1])
    base_us, seq_c, seq_s = 1_700_000_000_000_000, 1000, 5000
    for i in range(1, n+1):
        t = base_us + i * 1000
        req = frame(i, 0, t*1000, 0, 0); resp = frame(i, 1, t*1000, (t+40)*1000, (t+55)*1000)
        out.append(packet(t, a, b, 40000, 9100, seq_c, req)); seq_c += len(req)
        out.append(packet(t+85, a, b, 9100, 40000, seq_s, resp)); seq_s += len(resp)
    open(path, 'wb').write(b''.join(out))
    print(f'wrote {path} with {n} request/response pairs')

if __name__ == '__main__':
    main(*sys.argv[1:])
