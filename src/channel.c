#include "shadowvpn.h"

#include <errno.h>
#include <sodium.h>

#ifndef TARGET_WIN32
#include <sys/select.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#endif

#include "log.h"
#include "channel.h"

#ifndef TARGET_WIN32
//TODO: this is copy from vpn.c, need move it to common.h
static int max(int a, int b) {
  return a > b ? a : b;
}
#endif

int channel_udp_addr(const char *host, int port, struct sockaddr *addr, socklen_t* addrlen) {
  struct addrinfo hints;
  struct addrinfo *res;
  int r;

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  if (0 != (r = getaddrinfo(host, NULL, &hints, &res))) {
    errf("getaddrinfo: %s", gai_strerror(r));
    return -1;
  }

  if (res->ai_family == AF_INET)
    ((struct sockaddr_in *)res->ai_addr)->sin_port = htons(port);
  else if (res->ai_family == AF_INET6)
    ((struct sockaddr_in6 *)res->ai_addr)->sin6_port = htons(port);
  else {
    errf("unknown ai_family %d", res->ai_family);
    freeaddrinfo(res);
    return -1;
  }
  memcpy(addr, res->ai_addr, res->ai_addrlen);
  *addrlen = res->ai_addrlen;
	freeaddrinfo(res);

  return 0;
}

int channel_udp_alloc(int if_bind, const char *host, int port,
                  struct sockaddr *addr, socklen_t* addrlen) {
  struct addrinfo hints;
  struct addrinfo *res;
  int sock, r, flags;

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  if (0 != (r = getaddrinfo(host, NULL, &hints, &res))) {
    errf("getaddrinfo: %s", gai_strerror(r));
    return -1;
  }

  if (res->ai_family == AF_INET)
    ((struct sockaddr_in *)res->ai_addr)->sin_port = htons(port);
  else if (res->ai_family == AF_INET6)
    ((struct sockaddr_in6 *)res->ai_addr)->sin6_port = htons(port);
  else {
    errf("unknown ai_family %d", res->ai_family);
    freeaddrinfo(res);
    return -1;
  }

	if(addr != NULL && addrlen != NULL){
	  memcpy(addr, res->ai_addr, res->ai_addrlen);
	  *addrlen = res->ai_addrlen;
	}
  if (-1 == (sock = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP))) {
    err("socket");
    errf("can not create socket");
    freeaddrinfo(res);
    return -1;
  }

  if (if_bind) {
    if (0 != bind(sock, res->ai_addr, res->ai_addrlen)) {
      err("bind");
      errf("can not bind %s:%d", host, port);
      close(sock);
      freeaddrinfo(res);
      return -1;
    }
  }
  freeaddrinfo(res);

#ifndef TARGET_WIN32
  flags = fcntl(sock, F_GETFL, 0);
  if (flags != -1) {
    if (-1 != fcntl(sock, F_SETFL, flags | O_NONBLOCK))
      return sock;
  }
  err("fcntl");
#else
  u_long mode = 0;
  if (NO_ERROR == ioctlsocket(sock, FIONBIO, &mode))
    return disable_reset_report(sock);
  err("ioctlsocket");
#endif

  close(sock);
  return -1;
}

//bind is used for bind fixed ports
vpn_channel_t *channel_init(shadowvpn_args_t *args, int bind)
{
	int i = 0;
	vpn_channel_t *ch =  malloc(sizeof(vpn_channel_t));

	if (args->mode == SHADOWVPN_MODE_SERVER) {
		ch->nsock = args->channels;
	} else {
		// if we are client, we should have multiple sockets for each port
		ch->nsock = args->channels;
	}
	ch->socks = calloc(ch->nsock, sizeof(int));
	for (i = 0; i < ch->nsock; i++) {
		int *sock = ch->socks + i;

		//this will bind port dynamic, so can't run it in docker
		if (-1 == (*sock = channel_udp_alloc(bind,//args->mode == SHADOWVPN_MODE_SERVER,
											 "0.0.0.0", args->port + i,
											 NULL,
											 NULL))) {
			errf("failed to create UDP socket");
			return NULL;
		}
	}

	return ch;
}

int channel_deinit(vpn_channel_t *ch)
{
	int i;

	for (i = 0; i < ch->nsock; i++) {
		close(ch->socks[i]);
	}
	free(ch->socks);

	return 0;
}

int channel_set_fd(vpn_channel_t *ch, fd_set *set)
{
	int i = 0, max_fd = 0;

	for (i = 0; i < ch->nsock; i++) {
		FD_SET(ch->socks[i], set);
		max_fd = max(max_fd, ch->socks[i]);
	}

	return max_fd;
}

static int channel_choose_socket(vpn_channel_t *ch, int id)
{
  uint32_t r;
  if (ch->nsock == 1) {
    return ch->socks[0];
  }
  if(id >= 0){
	r = (id)%ch->nsock;
	if(id > ch->nsock){
		errf("id:%d > nsock:%d", id, ch->nsock);
	}
  }else {
	r = randombytes_uniform(ch->nsock);
  }
  return ch->socks[r];
}

int channel_send_data(vpn_channel_t *ch, int channel_id, unsigned char *buf, int len,  struct sockaddr *addr,  socklen_t addrlen)
{
	int sock = channel_choose_socket(ch, channel_id);

	ssize_t r = sendto(sock, buf, len, 0, addr, addrlen);
	if (r == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			// do nothing
		} else if (errno == ENETUNREACH || errno == ENETDOWN ||
							 errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
			// just log, do nothing
			err("sendto");
		} else {
			err("sendto");
			// TODO rebuild socket
			return -1;
		}
	}
	return 0;
}

int channel_recv_data(vpn_channel_t *ch, fd_set *set,
			unsigned char *buf, int len, void *ctx,
			int (*handler)(void*, int, unsigned char *, ssize_t , struct sockaddr_storage *, socklen_t ))
{
	int id;
  ssize_t r;
	// only change remote addr if decryption succeeds
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);

	for (id = 0; id <= ch->nsock; id++) {
		int sock = ch->socks[id];
		if (FD_ISSET(sock, set)) {
 			r = recvfrom(sock, buf, len, 0, (struct sockaddr *)&addr,	&addrlen);
			if (r == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					// do nothing
				} else if (errno == ENETUNREACH || errno == ENETDOWN ||
									errno == EPERM || errno == EINTR) {
					// just log, do nothing
					err("recvfrom");
				} else {
					err("recvfrom");
					// TODO rebuild socket
					break;
				}
			}
			if (r <= 0)
				continue;

			handler(ctx, id, buf, r - SHADOWVPN_OVERHEAD_LEN, &addr, addrlen);
		}
	}
	return 0;
}




