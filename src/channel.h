#ifndef CHANNEL_H
#define CHANNEL_H
#include "shadowvpn.h"

#ifdef TARGET_WIN32
#include "win32.h"
#else
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include <unistd.h>
#include <sys/types.h>

#ifndef TARGET_WIN32
#include <sys/socket.h>
#endif
//#include "args.h"

typedef struct {
  int nsock;
  int *socks;
}vpn_channel_t;

int channel_udp_alloc(int if_bind, const char *host, int port,
                  struct sockaddr *addr, socklen_t* addrlen);

vpn_channel_t *channel_init(shadowvpn_args_t *args, struct sockaddr *addr, socklen_t* addrlen);
int channel_deinit(vpn_channel_t *ch);
int channel_set_fd(vpn_channel_t *ch, fd_set *set);
int channel_send_data(vpn_channel_t *ch, unsigned char *buf, int len,  struct sockaddr *addr,  socklen_t addrlen);
int channel_recv_data(vpn_channel_t *ch, fd_set *set,
			unsigned char *buf, int len, void *ctx,
			int (*handler)(void*, unsigned char *, ssize_t , struct sockaddr_storage *, socklen_t ));

#endif
