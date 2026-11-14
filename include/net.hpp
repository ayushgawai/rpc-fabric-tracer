#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <stdexcept>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#if defined(__linux__)
#include <sys/epoll.h>
#elif defined(__APPLE__)
#include <sys/event.h>
#else
#include <poll.h>
#endif

namespace rpc {
inline void set_nonblocking(int fd){ int f=fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,f|O_NONBLOCK); }
inline void set_nodelay(int fd){ int v=1; setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&v,sizeof(v)); }
inline int tcp_listen(const char* host, uint16_t port) {
  addrinfo hints{}, *res=nullptr; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM; hints.ai_flags=AI_PASSIVE;
  if(getaddrinfo(host, std::to_string(port).c_str(), &hints, &res)) throw std::runtime_error("getaddrinfo listen");
  int fd=-1;
  for(auto* r=res;r;r=r->ai_next){ fd=socket(r->ai_family,r->ai_socktype,r->ai_protocol); if(fd<0) continue;
    int v=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&v,sizeof(v));
    if(!bind(fd,r->ai_addr,r->ai_addrlen) && !listen(fd,128)) break; close(fd); fd=-1; }
  freeaddrinfo(res); if(fd<0) throw std::runtime_error("listen failed"); set_nonblocking(fd); return fd;
}
inline int tcp_connect(const char* host, uint16_t port) {
  addrinfo hints{}, *res=nullptr; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
  if(getaddrinfo(host, std::to_string(port).c_str(), &hints, &res)) throw std::runtime_error("getaddrinfo connect");
  int fd=-1;
  for(auto* r=res;r;r=r->ai_next){ fd=socket(r->ai_family,r->ai_socktype,r->ai_protocol); if(fd<0) continue;
    if(!connect(fd,r->ai_addr,r->ai_addrlen)) break; close(fd); fd=-1; }
  freeaddrinfo(res); if(fd<0) throw std::runtime_error("connect failed"); set_nodelay(fd); return fd;
}
// writev all iovecs (blocking fd or already-ready nonblocking fd); returns false on EOF/error.
inline bool writev_all(int fd, struct iovec* iov, int cnt) {
  while(cnt>0){ ssize_t n=::writev(fd,iov,cnt); if(n<0){ if(errno==EINTR) continue; if(errno==EAGAIN) { struct pollfd p{fd,POLLOUT,0}; poll(&p,1,1000); continue; } return false; }
    while(n>0 && cnt>0){ if((size_t)n >= iov[0].iov_len){ n-=iov[0].iov_len; iov++; cnt--; } else { iov[0].iov_base=(char*)iov[0].iov_base+n; iov[0].iov_len-=n; n=0; } } }
  return true;
}
inline bool send_all(int fd, const uint8_t* p, size_t n){ struct iovec iov{(void*)p,n}; return writev_all(fd,&iov,1); }

// Minimal readiness poller: epoll (Linux) / kqueue (macOS) / poll (fallback).
// ponytail: level-triggered, single-threaded; add EPOLLET + thread pool only if profiling demands it.
class Poller {
public:
#if defined(__linux__)
  Poller(){ fd_=epoll_create1(0); }
  ~Poller(){ close(fd_); }
  void add(int fd){ epoll_event e{}; e.events=EPOLLIN; e.data.fd=fd; epoll_ctl(fd_,EPOLL_CTL_ADD,fd,&e); }
  void del(int fd){ epoll_ctl(fd_,EPOLL_CTL_DEL,fd,nullptr); }
  int wait(int* out, int max, int timeout_ms){ epoll_event ev[64]; int n=epoll_wait(fd_,ev,max<64?max:64,timeout_ms); for(int i=0;i<n;i++) out[i]=ev[i].data.fd; return n; }
  int fd_;
#elif defined(__APPLE__)
  Poller(){ fd_=kqueue(); }
  ~Poller(){ close(fd_); }
  void add(int fd){ struct kevent e; EV_SET(&e,fd,EVFILT_READ,EV_ADD,0,0,nullptr); kevent(fd_,&e,1,nullptr,0,nullptr); }
  void del(int fd){ struct kevent e; EV_SET(&e,fd,EVFILT_READ,EV_DELETE,0,0,nullptr); kevent(fd_,&e,1,nullptr,0,nullptr); }
  int wait(int* out, int max, int timeout_ms){ struct kevent ev[64]; timespec ts{timeout_ms/1000,(timeout_ms%1000)*1000000L}; int n=kevent(fd_,nullptr,0,ev,max<64?max:64,timeout_ms<0?nullptr:&ts); for(int i=0;i<n;i++) out[i]=(int)ev[i].ident; return n; }
  int fd_;
#else
  void add(int fd){ fds_.push_back(fd); }
  void del(int fd){ fds_.erase(std::remove(fds_.begin(),fds_.end(),fd),fds_.end()); }
  int wait(int* out, int max, int timeout_ms){ std::vector<pollfd> p; for(int fd:fds_) p.push_back({fd,POLLIN,0}); int n=poll(p.data(),p.size(),timeout_ms); int c=0; for(auto&x:p) if(x.revents&&c<max) out[c++]=x.fd; return n<0?n:c; }
  std::vector<int> fds_;
#endif
};
} // namespace rpc
