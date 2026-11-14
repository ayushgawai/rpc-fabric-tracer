#include "rpc.hpp"
#include "net.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <fstream>
#include <sstream>
// Link bring-up health checker: TCP-connect RTT distribution, negotiated MSS (MTU proxy),
// and TCP retransmit counters from /proc/net/snmp (Linux; graceful fallback elsewhere).
int main(int argc, char** argv){
  const char* host="127.0.0.1"; uint16_t port=9100; int samples=20;
  for(int i=1;i<argc;i++){ std::string a=argv[i];
    if(a=="--host"&&i+1<argc) host=argv[++i]; else if(a=="--port"&&i+1<argc) port=uint16_t(atoi(argv[++i]));
    else if(a=="--samples"&&i+1<argc) samples=atoi(argv[++i]); }
  std::printf("linkcheck host=%s port=%u\n", host, port);
  std::vector<double> rtt_us; int mss=0;
  for(int i=0;i<samples;i++){ uint64_t t0=rpc::now_ns();
    try{ int fd=rpc::tcp_connect(host,port); rtt_us.push_back((rpc::now_ns()-t0)/1000.0);
      socklen_t len=sizeof(mss); getsockopt(fd,IPPROTO_TCP,TCP_MAXSEG,&mss,&len); close(fd); }
    catch(...){ std::printf("connectivity: FAIL (sample %d)\n", i); return 1; } }
  std::sort(rtt_us.begin(), rtt_us.end());
  auto pct=[&](double p){ return rtt_us[size_t(p*(rtt_us.size()-1))]; };
  std::printf("connectivity: OK (%zu/%d connects)\n", rtt_us.size(), samples);
  std::printf("rtt_us (tcp connect) p50=%.1f p99=%.1f max=%.1f\n", pct(.5), pct(.99), rtt_us.back());
  std::printf("tcp_maxseg=%d bytes (path MTU >= %d on this socket; loopback usually 65495)\n", mss, mss+40);
#if defined(__linux__)
  std::ifstream f("/proc/net/snmp"); std::string line, prev;
  long retrans=-1, outsegs=-1;
  while(std::getline(f,line)){ if(line.rfind("Tcp:",0)==0){ if(!prev.empty()&&prev.rfind("Tcp:",0)==0){
      std::istringstream h(prev), v(line); std::string tok, val; std::vector<std::string> hs, vs;
      while(h>>tok) hs.push_back(tok); while(v>>val) vs.push_back(val);
      for(size_t i=0;i<hs.size()&&i<vs.size();i++){ if(hs[i]=="RetransSegs") retrans=atol(vs[i].c_str()); if(hs[i]=="OutSegs") outsegs=atol(vs[i].c_str()); } }
    prev=line; } }
  if(retrans>=0) std::printf("tcp RetransSegs=%ld OutSegs=%ld retrans_ratio=%.4f%% (/proc/net/snmp, host-wide)\n", retrans, outsegs, outsegs?100.0*retrans/outsegs:0);
  else std::printf("retransmits: /proc/net/snmp present but Tcp counters not parsed\n");
#else
  std::printf("retransmits: unavailable on this OS (no /proc/net/snmp); use `netstat -s -p tcp` on macOS\n");
#endif
  return 0;
}
