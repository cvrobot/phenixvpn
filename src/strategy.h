/**
  strategy.h

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

#ifndef STRATEGY_H
#define STRATEGY_H

#ifdef TARGET_WIN32
#include "win32.h"
#else
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif



/* the structure to store known client addresses for the server */
typedef struct {
  struct sockaddr_storage addr;
  socklen_t addrlen;
  time_t last_recv_time;
} addr_info_t;

typedef struct {  /* known client addrs for the server */
  int nknown_addr;
  addr_info_t *known_addrs;

  int index;//chose start index of addrs.
  uint32_t addr_mask;
}strategy_info_t;

typedef enum{
	STRATEGY_RND,
	STRATEGY_TIME,
}strategy_type;

typedef struct {
  strategy_info_t *info;
  int index;//choose start index of strategys.
  int strategys;
  int *strategys_hop;//channel hop
  int strategys_hop_no;
  int addrs;//concurrent
  int *addrs_hop;//concurrent hop
  int addrs_hop_no;
  int timeout;
  strategy_type type;
}strategy_ctx_t;

//#define UDP_TIMEOUT (120/2)

strategy_ctx_t *strategy_init(uint16_t concurrency, uint16_t channels, int timeout);

// choose a reasonable remote address based on magic
// update ctx->remote_addr and remote_addrlen
// return 0 on success
int strategy_choose_remote_addr(strategy_ctx_t *ctx, int *channel_id, struct sockaddr *remote_addrp, socklen_t *remote_addrlen);

// update remote address list from remote_addr and remote_addrlen
void strategy_update_remote_addr_list(strategy_ctx_t *cli, int channel_id, struct sockaddr *remote_addrp, socklen_t remote_addrlen);
#endif
