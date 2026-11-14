#include "rpc.hpp"
#include "client.hpp"
#include <cassert>
#include <cstdio>
int main(){
  // framing: round-trip, split feeds, batch ids
  auto m = rpc::Message{42,0,1,0,100,0,0,{'h','i'}};
  auto bytes = rpc::encode(m);
  rpc::Decoder d; std::vector<rpc::Message> out;
  for(uint8_t b: bytes){ uint8_t x=b; assert(d.feed(&x,1,out)); } // byte-at-a-time must not lose the frame
  assert(out.size()==1 && out[0].id==42 && out[0].body.size()==2);
  // corrupt length rejected
  rpc::Decoder bad; std::vector<rpc::Message> o2; uint8_t junk[4]={0,0,0,1}; assert(!bad.feed(junk,4,o2));
  // batching: 8 messages, consecutive ids, decode all from one buffer
  auto batch = rpc::make_batch(100, 7, std::vector<uint8_t>{1,2,3}, 8);
  std::vector<uint8_t> all; for(auto& x: batch){ auto e=rpc::encode(x); all.insert(all.end(),e.begin(),e.end()); }
  rpc::Decoder d2; std::vector<rpc::Message> got; assert(d2.feed(all.data(), all.size(), got));
  assert(got.size()==8); for(int i=0;i<8;i++) assert(got[i].id==100+i && got[i].op==7);
  std::puts("test_framing OK");
}
