#pragma once
#include "rpc.hpp"
#include "net.hpp"
#include <unordered_map>
namespace rpc {
// Pipelined client: sends a batch with one writev, reads responses with readv until all ids return.
class Client {
public:
  Client(const char* host, uint16_t port){ fd_=tcp_connect(host,port); }
  ~Client(){ close(fd_); }
  // Returns per-request latency ns (send-batch-start -> that response decoded).
  std::vector<uint64_t> call_batch(const std::vector<Message>& reqs) {
    std::vector<std::vector<uint8_t>> frames; std::vector<struct iovec> iov;
    uint64_t t0 = now_ns();
    for(auto& m: reqs){ frames.push_back(encode(m)); }
    for(auto& f: frames) iov.push_back({f.data(), f.size()});
    if(!writev_all(fd_, iov.data(), int(iov.size()))) throw std::runtime_error("write failed");
    std::unordered_map<uint64_t,uint64_t> lat; Decoder dec; size_t got=0;
    while(got<reqs.size()){
      char a[8192], b[8192]; struct iovec riov[2]{{a,sizeof a},{b,sizeof b}};
      ssize_t r=::readv(fd_, riov, 2); if(r<=0) throw std::runtime_error("read failed");
      std::vector<Message> msgs;
      bool ok = r<=8192 ? dec.feed((uint8_t*)a,r,msgs) : (dec.feed((uint8_t*)a,8192,msgs)&&dec.feed((uint8_t*)b,r-8192,msgs));
      if(!ok) throw std::runtime_error("decode failed");
      uint64_t t1=now_ns(); for(auto& m: msgs){ lat[m.id]=t1-t0; got++; }
    }
    std::vector<uint64_t> out; for(auto& m: reqs) out.push_back(lat[m.id]); return out;
  }
  int fd_;
};
} // namespace rpc
