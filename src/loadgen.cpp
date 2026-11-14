#include "client.hpp"
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <numeric>
// Load generator: N pipelined batches over one connection; reports throughput + p50/p99/p99.9.
// ponytail: one connection by default; scale with --conns processes if you need multi-core load.
int main(int argc, char** argv){
  const char* host="127.0.0.1"; uint16_t port=9100; int requests=20000, batch=32, payload=64;
  for(int i=1;i<argc;i++){ std::string a=argv[i];
    if(a=="--host"&&i+1<argc) host=argv[++i]; else if(a=="--port"&&i+1<argc) port=atoi(argv[++i]);
    else if(a=="--requests"&&i+1<argc) requests=atoi(argv[++i]); else if(a=="--batch"&&i+1<argc) batch=atoi(argv[++i]);
    else if(a=="--payload"&&i+1<argc) payload=atoi(argv[++i]); }
  rpc::Client c(host, port);
  std::vector<uint8_t> body(payload, 'x');
  std::vector<uint64_t> lat; lat.reserve(requests);
  uint64_t id=1; auto t0=rpc::now_ns(); int done=0;
  while(done<requests){ int n=std::min(batch, requests-done);
    auto reqs=rpc::make_batch(id, 1, body, n); id+=n;
    for(uint64_t l: c.call_batch(reqs)) lat.push_back(l); done+=n; }
  double secs=(rpc::now_ns()-t0)/1e9;
  std::sort(lat.begin(), lat.end());
  auto pct=[&](double p){ return lat[std::min<size_t>(lat.size()-1, size_t(p*lat.size()))]/1000.0; };
  std::printf("requests=%d batch=%d payload=%d\n", requests, batch, payload);
  std::printf("throughput=%.0f req/s  elapsed=%.3fs\n", requests/secs, secs);
  std::printf("latency_us p50=%.1f p99=%.1f p99.9=%.1f max=%.1f\n", pct(0.50), pct(0.99), pct(0.999), lat.back()/1000.0);
}
