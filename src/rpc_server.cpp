#include "rpc.hpp"
#include "net.hpp"
#include <cstdio>
#include <cstdlib>
#include <unordered_map>
// Echo RPC server: stamps server_recv/send (realtime ns, comparable to pcap timestamps),
// batches all pending responses per connection into one writev (scatter-gather: header+body iovecs).
int main(int argc, char** argv){
  uint16_t port = argc>1 ? uint16_t(atoi(argv[1])) : 9100;
  int lfd = rpc::tcp_listen("0.0.0.0", port);
  rpc::Poller poller; poller.add(lfd);
  struct Conn { rpc::Decoder dec; };
  std::unordered_map<int, Conn> conns;
  std::fprintf(stderr, "rpc_server listening on %u\n", port);
  int ready[64];
  for(;;){
    int n = poller.wait(ready, 64, -1);
    for(int i=0;i<n;i++){
      int fd = ready[i];
      if(fd==lfd){ int c; while((c=accept(lfd,nullptr,nullptr))>=0){ rpc::set_nonblocking(c); rpc::set_nodelay(c); poller.add(c); conns[c]={}; } continue; }
      // readv into two buffers (scatter read), then decode every complete frame
      char a[8192], b[8192]; struct iovec iov[2]{{a,sizeof a},{b,sizeof b}};
      ssize_t r = ::readv(fd, iov, 2);
      if(r<=0){ poller.del(fd); close(fd); conns.erase(fd); continue; }
      auto& conn = conns[fd];
      std::vector<rpc::Message> msgs;
      bool ok = (r<=8192) ? conn.dec.feed((uint8_t*)a, r, msgs)
                          : (conn.dec.feed((uint8_t*)a,8192,msgs) && conn.dec.feed((uint8_t*)b, r-8192, msgs));
      if(!ok){ poller.del(fd); close(fd); conns.erase(fd); continue; }
      if(msgs.empty()) continue;
      // Build one writev: per response, [frame bytes] is split logically as header iov + body iov.
      std::vector<std::vector<uint8_t>> frames; frames.reserve(msgs.size());
      std::vector<struct iovec> out; out.reserve(msgs.size()*2);
      for(auto& m: msgs){
        rpc::Message resp; resp.id=m.id; resp.type=1; resp.op=m.op;
        resp.client_send_ns=m.client_send_ns; resp.server_recv_ns=rpc::now_ns(); resp.server_send_ns=resp.server_recv_ns;
        resp.body=m.body; // echo
        frames.push_back(rpc::encode(resp));
        auto& f = frames.back();
        // stamp send time just before writev (approx: same for batch)
        out.push_back({f.data(), f.size()});
      }
      uint64_t send_ns = rpc::now_ns();
      for(size_t k=0;k<frames.size();k++) rpc::put64(frames[k].data()+4+28, send_ns); // server_send_ns offset
      rpc::writev_all(fd, out.data(), int(out.size()));
    }
  }
}
