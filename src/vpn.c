/**
  vpn.c

  Copyright (C) 2015 clowwindy

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

// TODO we want to put shadowvpn.h at the bottom of the imports
// but TARGET_* is defined in config.h
#include "shadowvpn.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#ifndef TARGET_WIN32
#include <sys/select.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#endif

#ifdef TARGET_DARWIN
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <sys/sys_domain.h>
#include <netinet/ip.h>
#include <sys/uio.h>
#endif

#ifdef TARGET_LINUX
#include <linux/if_tun.h>
#endif

#ifdef TARGET_FREEBSD
#include <net/if_tun.h>
#endif


/*
 * Darwin & OpenBSD use utun which is slightly
 * different from standard tun device. It adds
 * a uint32 to the beginning of the IP header
 * to designate the protocol.
 *
 * We use utun_read to strip off the header
 * and utun_write to put it back.
 */
#ifdef TARGET_DARWIN
#define tun_read(...) utun_read(__VA_ARGS__)
#define tun_write(...) utun_write(__VA_ARGS__)
#elif !defined(TARGET_WIN32)
#define tun_read(...) read(__VA_ARGS__)
#define tun_write(...) write(__VA_ARGS__)
#endif

#ifdef TARGET_WIN32

#undef errno
#undef EWOULDBLOCK
#undef EAGAIN
#undef EINTR
#undef ENETDOWN
#undef ENETUNREACH
#undef EMSGSIZE

#define errno WSAGetLastError()
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EAGAIN WSAEWOULDBLOCK
#define EINTR WSAEINTR
#define ENETUNREACH WSAENETUNREACH
#define ENETDOWN WSAENETDOWN
#define EMSGSIZE WSAEMSGSIZE
#define close(fd) closesocket(fd)

#endif

#ifdef TARGET_LINUX
int vpn_tun_alloc(const char *dev) {
  struct ifreq ifr;
  int fd, e;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    err("open");
    errf("can not open /dev/net/tun");
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if(*dev)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if ((e = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
    err("ioctl[TUNSETIFF]");
    errf("can not setup tun device: %s", dev);
    close(fd);
    return -1;
  }
  // strcpy(dev, ifr.ifr_name);
  return fd;
}
#endif

#ifdef TARGET_FREEBSD
int vpn_tun_alloc(const char *dev) {
  int fd;
  char devname[32]={0,};
  snprintf(devname, sizeof(devname), "/dev/%s", dev);
  if ((fd = open(devname, O_RDWR)) < 0) {
    err("open");
    errf("can not open %s", devname);
    return -1;
  }
  int i = IFF_POINTOPOINT | IFF_MULTICAST;
  if (ioctl(fd, TUNSIFMODE, &i) < 0) {
    err("ioctl[TUNSIFMODE]");
    errf("can not setup tun device: %s", dev);
    close(fd);
    return -1;
  }
  i = 0;
  if (ioctl(fd, TUNSIFHEAD, &i) < 0) {
    err("ioctl[TUNSIFHEAD]");
    errf("can not setup tun device: %s", dev);
    close(fd);
    return -1;
  }
  return fd;
}
#endif

#ifdef TARGET_DARWIN
static inline int utun_modified_len(int len) {
  if (len > 0)
    return (len > sizeof (u_int32_t)) ? len - sizeof (u_int32_t) : 0;
  else
    return len;
}

static int utun_write(int fd, void *buf, size_t len) {
  u_int32_t type;
  struct iovec iv[2];
  struct ip *iph;

  iph = (struct ip *) buf;

  if (iph->ip_v == 6)
    type = htonl(AF_INET6);
  else
    type = htonl(AF_INET);

  iv[0].iov_base = &type;
  iv[0].iov_len = sizeof(type);
  iv[1].iov_base = buf;
  iv[1].iov_len = len;

  return utun_modified_len(writev(fd, iv, 2));
}

static int utun_read(int fd, void *buf, size_t len) {
  u_int32_t type;
  struct iovec iv[2];

  iv[0].iov_base = &type;
  iv[0].iov_len = sizeof(type);
  iv[1].iov_base = buf;
  iv[1].iov_len = len;

  return utun_modified_len(readv(fd, iv, 2));
}

int vpn_tun_alloc(const char *dev) {
  struct ctl_info ctlInfo;
  struct sockaddr_ctl sc;
  int fd;
  int utunnum;

  if (dev == NULL) {
    errf("utun device name cannot be null");
    return -1;
  }
  if (sscanf(dev, "utun%d", &utunnum) != 1) {
    errf("invalid utun device name: %s", dev);
    return -1;
  }

  memset(&ctlInfo, 0, sizeof(ctlInfo));
  if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >=
      sizeof(ctlInfo.ctl_name)) {
    errf("can not setup utun device: UTUN_CONTROL_NAME too long");
    return -1;
  }

  fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

  if (fd == -1) {
    err("socket[SYSPROTO_CONTROL]");
    return -1;
  }

  if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1) {
    close(fd);
    err("ioctl[CTLIOCGINFO]");
    return -1;
  }

  sc.sc_id = ctlInfo.ctl_id;
  sc.sc_len = sizeof(sc);
  sc.sc_family = AF_SYSTEM;
  sc.ss_sysaddr = AF_SYS_CONTROL;
  sc.sc_unit = utunnum + 1;

  if (connect(fd, (struct sockaddr *) &sc, sizeof(sc)) == -1) {
    close(fd);
    err("connect[AF_SYS_CONTROL]");
    return -1;
  }

  return fd;
}
#endif

#ifdef TARGET_WIN32
static int tun_write(int tun_fd, char *data, size_t len) {
  DWORD written;
  DWORD res;
  OVERLAPPED olpd;

  olpd.Offset = 0;
  olpd.OffsetHigh = 0;
  olpd.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  res = WriteFile(dev_handle, data, len, &written, &olpd);
  if (!res && GetLastError() == ERROR_IO_PENDING) {
    WaitForSingleObject(olpd.hEvent, INFINITE);
    res = GetOverlappedResult(dev_handle, &olpd, &written, FALSE);
    if (written != len) {
      return -1;
    }
  }
  return 0;
}

static int tun_read(int tun_fd, char *buf, size_t len) {
  return recv(tun_fd, buf, len, 0);
}
#endif

#ifndef TARGET_WIN32
static int max(int a, int b) {
  return a > b ? a : b;
}
#endif

int vpn_ctx_init(vpn_ctx_t *ctx, shadowvpn_args_t *args) {
  int i;
  struct sockaddr *def_addr = NULL;
  socklen_t def_addrlen = 0;
#ifdef TARGET_WIN32
  WORD wVersionRequested;
  WSADATA wsaData;
  int ret;

  wVersionRequested = MAKEWORD(1, 1);
  ret = WSAStartup(wVersionRequested, &wsaData);
  if (ret != 0) {
    errf("can not initialize winsock");
    return -1;
  }
  if (LOBYTE(wsaData.wVersion) != 1 || HIBYTE(wsaData.wVersion) != 1) {
    WSACleanup();
    errf("can not find a usable version of winsock");
    return -1;
  }
#endif

  bzero(ctx, sizeof(vpn_ctx_t));
  ctx->remote_addrp = (struct sockaddr *)&ctx->remote_addr;

#ifndef TARGET_WIN32
  if (-1 == pipe(ctx->control_pipe)) {
    err("pipe");
    return -1;
  }
  if (-1 == (ctx->tun = vpn_tun_alloc(args->intf))) {
    errf("failed to create tun device");
    return -1;
  }
#else
  if (-1 == (ctx->control_fd = channel_udp_alloc(1, TUN_DELEGATE_ADDR,
                                             args->tun_port + 1,
                                             &ctx->control_addr,
                                             &ctx->control_addrlen))) {
    err("failed to create control socket");
    return -1;
  }
  if (NULL == (ctx->cleanEvent = CreateEvent(NULL, TRUE, FALSE, NULL))) {
    err("CreateEvent");
    return -1;
  }
  if (-1 == (ctx->tun = tun_open(args->intf, args->net_ip, args->net_mask,
                                 args->tun_port))) {
    errf("failed to create tun device");
    return -1;
  }
#endif

	ctx->channel = channel_init(args, ctx->remote_addrp, &ctx->remote_addrlen);
	if(ctx->channel == NULL){
		close(ctx->tun);
		return -1;
	}
	if(args->mode == SHADOWVPN_MODE_CLIENT){
		args->clients = 1;//set this before client_init, because client is both used by srv and cli
		//set default remote addr for client side, client will send data first.
		def_addr = ctx->remote_addrp;
		def_addrlen = ctx->remote_addrlen;
	}
	
	ctx->cli_ctx = client_init(args, def_addr, def_addrlen);
	if(ctx->cli_ctx == NULL)
		return -1;
  ctx->args = args;
  return 0;
}

int vpn_handle_read_data(void * args, unsigned char *buf, ssize_t len, struct sockaddr_storage *addr, socklen_t addrlen)
{
	vpn_ctx_t *ctx = (vpn_ctx_t *)args;
	cli_ctx_t *cli_ctx = ctx->cli_ctx;
	uint32_t netip;
	//buf is equal to ctx->udp_buf + SHADOWVPN_PACKET_OFFSET, so data is already read to udp_buf;

	crypto_get_token(ctx->udp_buf, &netip);
	if(get_client_by_netip(cli_ctx, netip))
		return -1;
	if (-1 == crypto_decrypt_ext(ctx->tun_buf, ctx->udp_buf,
													len, cli_ctx->cli->key)) {
		errf("dropping invalid packet, maybe wrong password");
		return 0;
	} else {
		// update remote address from recvfrom
		// recv_from
		memcpy(ctx->remote_addrp, addr, addrlen);
		ctx->remote_addrlen = addrlen;
		if(ctx->args->mode == SHADOWVPN_MODE_CLIENT){
			//get_client_by_daddr(cli_ctx, ctx->tun_buf + SHADOWVPN_ZERO_BYTES, len);
			//already set cli to cli_ctx at client_init
		}else{
			get_client_by_saddr(cli_ctx, ctx->tun_buf + SHADOWVPN_ZERO_BYTES, len);
		}

		// now we got one client address, update the address list
		if(cli_ctx->cli != NULL)
			strategy_update_remote_addr_list(cli_ctx->cli->strategy, ctx->remote_addrp, ctx->remote_addrlen);
		else{
			//can't find client, means this address is not added to client, so drop it.
			ctx->remote_addrlen = 0;
			errf("%s get client fail", __func__);
		}

		if(ctx->remote_addrlen){
			if (-1 == tun_write(ctx->tun, ctx->tun_buf + SHADOWVPN_ZERO_BYTES, len)) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					// do nothing
				} else if (errno == EPERM || errno == EINTR || errno == EINVAL) {
					// just log, do nothing
					err("write to tun");
				} else {
					err("write to tun");
					return -1;
				}
			}
		}
	}
	return 0;
}

int vpn_run(vpn_ctx_t *ctx) {
	cli_ctx_t *cli_ctx = ctx->cli_ctx;
  fd_set readset;
  int max_fd = 0, i;
  ssize_t r;
  if (ctx->running) {
    errf("can not start, already running");
    return -1;
  }

  ctx->running = 1;

  shell_up(ctx->args);

  ctx->tun_buf = malloc(ctx->args->mtu + SHADOWVPN_ZERO_BYTES);
  ctx->udp_buf = malloc(ctx->args->mtu + SHADOWVPN_ZERO_BYTES);
  bzero(ctx->tun_buf, SHADOWVPN_ZERO_BYTES);
  bzero(ctx->udp_buf, SHADOWVPN_ZERO_BYTES);

  logf("VPN started");

  while (ctx->running) {
    FD_ZERO(&readset);
#ifndef TARGET_WIN32
    FD_SET(ctx->control_pipe[0], &readset);
#else
    FD_SET(ctx->control_fd, &readset);
#endif
    FD_SET(ctx->tun, &readset);

		max_fd = channel_set_fd(ctx->channel, &readset);

    // we assume that pipe fd is always less than tun and sock fd which are
    // created later
    max_fd = max(ctx->tun, max_fd) + 1;

    if (-1 == select(max_fd, &readset, NULL, NULL, NULL)) {
      if (errno == EINTR)
        continue;
      err("select");
      break;
    }
#ifndef TARGET_WIN32
    if (FD_ISSET(ctx->control_pipe[0], &readset)) {
      char pipe_buf;
      r = read(ctx->control_pipe[0], &pipe_buf, 1);
      break;
    }
#else
    if (FD_ISSET(ctx->control_fd, &readset)) {
      char buf;
      recv(ctx->control_fd, &buf, 1, 0);
      break;
    }
#endif
    if (FD_ISSET(ctx->tun, &readset)) {
      r = tun_read(ctx->tun, ctx->tun_buf + SHADOWVPN_ZERO_BYTES,
                   ctx->args->mtu);
      if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // do nothing
        } else if (errno == EPERM || errno == EINTR) {
          // just log, do nothing
          err("read from tun");
        } else {
          err("read from tun");
          break;
        }
      }

		
		if(ctx->args->mode == SHADOWVPN_MODE_CLIENT){
			//for client we just get the only cli.
			//get_client_by_saddr(cli_ctx, ctx->tun_buf + SHADOWVPN_ZERO_BYTES, r);
			//already set cli to cli_ctx at client_init
		}else{
			get_client_by_daddr(cli_ctx, ctx->tun_buf + SHADOWVPN_ZERO_BYTES, r);
		}
		if(cli_ctx->cli != NULL){
			if(strategy_choose_remote_addr(cli_ctx->cli->strategy, ctx->remote_addrp, &ctx->remote_addrlen)){
				struct in_addr in;
				in.s_addr = cli_ctx->cli->output_tun_ip;
				errf("can't get remote addr,cli ip:%s",inet_ntoa(in));
			}
		}else{
			ctx->remote_addrlen = 0;
			//errf("%s get client fail", __func__);
		}
      if (ctx->remote_addrlen) {
        crypto_encrypt_ext(ctx->udp_buf, ctx->tun_buf, r, cli_ctx->cli->key);
				crypto_set_token(ctx->udp_buf, cli_ctx->cli->output_tun_ip);
		r = channel_send_data(ctx->channel, ctx->udp_buf,
           SHADOWVPN_OVERHEAD_LEN + r,
           ctx->remote_addrp, ctx->remote_addrlen);
        if (r == -1) {
          break;
        }
      }
    }

		channel_recv_data(ctx->channel, &readset, ctx->udp_buf,
				SHADOWVPN_OVERHEAD_LEN + ctx->args->mtu, (void*)ctx, vpn_handle_read_data);
  }
  free(ctx->tun_buf);
  free(ctx->udp_buf);

  shell_down(ctx->args);

  close(ctx->tun);
	channel_deinit(ctx->channel);
  ctx->running = 0;

#ifdef TARGET_WIN32
  close(ctx->control_fd);
  WSACleanup();
  SetEvent(ctx->cleanEvent);
#endif

  return -1;
}

int vpn_stop(vpn_ctx_t *ctx) {
  logf("shutting down by user");
  if (!ctx->running) {
    errf("can not stop, not running");
    return -1;
  }
  ctx->running = 0;
  char buf = 0;
#ifndef TARGET_WIN32
  if (-1 == write(ctx->control_pipe[1], &buf, 1)) {
    err("write");
    return -1;
  }
#else
  int send_sock;
  struct sockaddr addr;
  socklen_t addrlen;
  if (-1 == (send_sock = channel_udp_alloc(0, TUN_DELEGATE_ADDR, 0, &addr,
                                       &addrlen))) {
    errf("failed to init control socket");
    return -1;
  }
  if (-1 == sendto(send_sock, &buf, 1, 0, &ctx->control_addr,
                   ctx->control_addrlen)) {
    err("sendto");
    close(send_sock);
    return -1;
  }
  close(send_sock);
  WaitForSingleObject(ctx->cleanEvent, INFINITE);
  CloseHandle(ctx->cleanEvent);
#endif
  return 0;
}
