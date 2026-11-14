#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <chrono>

// Wire format (all integers big-endian):
//   frame:  u32 total_len (= HEADER_LEN + body_len) | header | body
//   header: u64 id | u8 type(0=req,1=resp) | u8 op | u16 flags
//           u64 client_send_ns | u64 server_recv_ns | u64 server_send_ns  (CLOCK_REALTIME ns)
// total_len excludes the 4-byte length prefix itself.
namespace rpc {
inline constexpr uint32_t kHeaderLen = 36;
inline constexpr uint32_t kMaxFrame = 16u << 20;

inline uint64_t now_ns() {
  return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}
inline void put32(uint8_t* p, uint32_t v){ p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }
inline void put64(uint8_t* p, uint64_t v){ for(int i=0;i<8;i++) p[i]=uint8_t(v>>(56-8*i)); }
inline uint32_t get32(const uint8_t* p){ return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3]; }
inline uint64_t get64(const uint8_t* p){ uint64_t v=0; for(int i=0;i<8;i++) v=(v<<8)|p[i]; return v; }

struct Message {
  uint64_t id=0; uint8_t type=0, op=0; uint16_t flags=0;
  uint64_t client_send_ns=0, server_recv_ns=0, server_send_ns=0;
  std::vector<uint8_t> body;
};

inline std::vector<uint8_t> encode(const Message& m) {
  std::vector<uint8_t> out(4 + kHeaderLen + m.body.size());
  put32(out.data(), uint32_t(kHeaderLen + m.body.size()));
  uint8_t* h = out.data()+4;
  put64(h, m.id); h[8]=m.type; h[9]=m.op; h[10]=uint8_t(m.flags>>8); h[11]=uint8_t(m.flags);
  put64(h+12, m.client_send_ns); put64(h+20, m.server_recv_ns); put64(h+28, m.server_send_ns);
  if(!m.body.empty()) std::memcpy(h+kHeaderLen, m.body.data(), m.body.size());
  return out;
}

// Incremental decoder: feed bytes, pop complete messages. Returns false on corrupt length.
struct Decoder {
  std::vector<uint8_t> buf;
  bool feed(const uint8_t* p, size_t n, std::vector<Message>& out) {
    buf.insert(buf.end(), p, p+n);
    size_t off=0;
    while (buf.size()-off >= 4) {
      uint32_t len = get32(buf.data()+off);
      if (len < kHeaderLen || len > kMaxFrame) return false;
      if (buf.size()-off < 4+len) break;
      const uint8_t* h = buf.data()+off+4;
      Message m; m.id=get64(h); m.type=h[8]; m.op=h[9]; m.flags=(uint16_t(h[10])<<8)|h[11];
      m.client_send_ns=get64(h+12); m.server_recv_ns=get64(h+20); m.server_send_ns=get64(h+28);
      m.body.assign(h+kHeaderLen, h+len);
      out.push_back(std::move(m)); off += 4+len;
    }
    buf.erase(buf.begin(), buf.begin()+off);
    return true;
  }
};

// Batch = several frames written with one writev (see server/client).
inline std::vector<Message> make_batch(uint64_t first_id, uint8_t op,
                                       const std::vector<uint8_t>& body, size_t n) {
  std::vector<Message> b; b.reserve(n);
  for(size_t i=0;i<n;i++){ Message m; m.id=first_id+i; m.type=0; m.op=op; m.client_send_ns=now_ns(); m.body=body; b.push_back(std::move(m)); }
  return b;
}
} // namespace rpc
