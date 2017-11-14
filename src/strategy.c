/**
  strategy.c

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

#include "shadowvpn.h"

#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#ifndef TARGET_WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <sodium.h>

#define ADDR_TIMEOUT 10


static int show_addr(const char *func, int channel_id, struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
	//windows only support inetNtop win8
	//inet_ntop(in_addr->sin_family, &in_addr->sin_addr.s_addr, s_addr, INET6_ADDRSTRLEN);

	if(in_addr->sin_family == AF_INET){
		logf("%s %s:channel_id:%d addr:%s,port:%d", func, __func__, channel_id, inet_ntoa(in_addr->sin_addr), ntohs(in_addr->sin_port));
	}else
		logf("%s %s: in_addr->sin_family not AF_INET:%d,", func, __func__, in_addr->sin_family);
	return 0;
}

static inline void save_addr(addr_info_t *addr_info, struct sockaddr *addrp,
                             socklen_t addrlen, time_t now) {
  memcpy(&addr_info->addr, addrp, addrlen);
  addr_info->addrlen = addrlen;
  addr_info->last_recv_time = now;
}

static inline void load_addr(addr_info_t *addr_info,
                             struct sockaddr *addr,
                             socklen_t *addrlen) {
  memcpy(addr, &addr_info->addr, addr_info->addrlen);
  *addrlen = addr_info->addrlen;
}

static int isPrime(int a, int b)
{
 int temp, i = 0;
 while(b!=0)
 {
   temp = b;
   b = a % b;
   a = temp;
   i++;
 }
 //printf("loop cont:%d\n",i);
 if(a==1)
  return 1;
 else
  return 0;
}

static int build_all_prime(int *list, int *num, int val)
{
	int i = 0, res;

	if(val < 1)
		return -1;
	if(val == 1)
		list[i++] = val;
	res = val - 1;

	while(res > 1) {
		if (isPrime(res, val)){
			list[i++] = res;
		//printf("%d is result\n", res);
		//break;
		}
		res--;
	}
	if(res == 1){
		list[i++] = 1;
	}
	*num = i;
	return 0;
}

static int get_random_hop(int* hop, int hop_count)
{
	int h;

	//this function return 0~t-1
	h = randombytes_uniform(hop_count);
	return hop[h];
}

strategy_ctx_t *strategy_init(uint16_t concurrency, uint16_t channels, int type)
{
	int i;
	strategy_ctx_t * ctx = malloc(sizeof(strategy_ctx_t) + sizeof(strategy_info_t) * channels);
	//ctx->info = (strategy_info_t *)(++ctx);
	ctx->info = (strategy_info_t *)((void*)ctx + sizeof(strategy_ctx_t));
	ctx->strategys = channels;
	ctx->strategys_hop = malloc(sizeof(int) * channels);
	ctx->addrs = concurrency;
	ctx->addrs_hop = malloc(sizeof(int) * concurrency);
	ctx->timeout = ADDR_TIMEOUT;
	ctx->type = type;
	if(type == STRATEGY_RND){
		channels = 1;
	}else{
		//build prime numbers for channel select
		build_all_prime(ctx->strategys_hop, &ctx->strategys_hop_no, ctx->strategys);
		//build prime numbers for concurrency addr select
		build_all_prime(ctx->addrs_hop, &ctx->addrs_hop_no, ctx->addrs);
		//for(i = 0; i <ctx->strategys_hop_no; i++)
		//	logf("%d,", ctx->strategys_hop[i]);
	}

	for(i = 0; i < channels; i++){
		ctx->info[i].nknown_addr = 0;
		ctx->info[i].addr_mask = 0;
		ctx->info[i].known_addrs = calloc(concurrency, sizeof(addr_info_t));
	}
	return ctx;
}

int strategy_choose_client_addr(strategy_ctx_t *ctx, int *channel_id, struct sockaddr *remote_addrp, socklen_t *remote_addrlen)
{
  // rules:
  // 1. from channel index search to channel index -1
  // 2. from info index to info index -1
  //    if index bit is set in valid_marsk, check time out, if timeout update valid_mask ,else choose it.
  //
  int i, c, x, y;
  time_t now;
  addr_info_t  *temp;
  strategy_info_t *info;

  time(&now);
	x = get_random_hop(ctx->strategys_hop, ctx->strategys_hop_no);
	for(c = 0; c < ctx->strategys; c++){
		*channel_id = ctx->index;
		logf("search ch:%d, hop:%d ctx->strategys:%d", ctx->index, x, ctx->strategys);
		info = &ctx->info[ctx->index];
		ctx->index = (ctx->index + x) % ctx->strategys;
		if(info->nknown_addr == 0 || info->addr_mask == 0)
			continue;

		y = get_random_hop(ctx->addrs_hop, ctx->addrs_hop_no);
		for(i = 0; i < ctx->addrs; i++){
			logf("search index:%d, hop:%d, ctx->addrs:%d", info->index, y, ctx->addrs);
			int index = info->index;
			info->index = (info->index + y) % ctx->addrs;
			if(info->addr_mask& (1<<index)){
				temp = &info->known_addrs[index];
				if (now - temp->last_recv_time < ctx->timeout) {
					load_addr(temp, remote_addrp, remote_addrlen);
					show_addr(__func__, *channel_id, remote_addrp, *remote_addrlen);
					return 0;
				}else{//update timeout
					info->addr_mask &= (~(1<<index));
				}
			}else{//already timeout, or this address is not added to known_addrs
				continue;
			}
		}
	}
  err("Can't find any remote addr");
  return -1;
}
int strategy_choose_server_addr(strategy_ctx_t *ctx, int *channel_id, struct sockaddr *remote_addrp, socklen_t *remote_addrlen)
{
	strategy_info_t *info = ctx->info;
	addr_info_t  *temp;
	int index;

	*channel_id = randombytes_uniform(ctx->strategys);
	index = randombytes_uniform(info->nknown_addr );
	temp = &info->known_addrs[index];
	load_addr(temp, remote_addrp, remote_addrlen);
	show_addr(__func__, *channel_id, remote_addrp, *remote_addrlen);
	return 0;
}

void strategy_update_server_addr_list(strategy_ctx_t *ctx, int channel_id, struct sockaddr *remote_addrp, socklen_t remote_addrlen)
{
	strategy_info_t *info = ctx->info;
	int i;
	time_t now;
	time(&now);

    for (i = 0; i < info->nknown_addr; i++) {
	    if (remote_addrlen == info->known_addrs[i].addrlen) {
	      if (0 == memcmp(remote_addrp, &info->known_addrs[i].addr,
	                      remote_addrlen)) {
			save_addr(&info->known_addrs[i], remote_addrp,
					  remote_addrlen, now);
			show_addr(__func__, channel_id, remote_addrp, remote_addrlen);
	        return;
	      }
	    }
	}
  // if address list is not full, just append remote addr
  if (info->nknown_addr < ctx->addrs) {
    save_addr(&info->known_addrs[info->nknown_addr], remote_addrp,
              remote_addrlen, now);
	show_addr(__func__, channel_id, remote_addrp, remote_addrlen);
    info->nknown_addr++;
    return;
  }
  errf("nknown_addr >= max_addrs");
}

//channel
void strategy_update_client_addr_list(strategy_ctx_t *ctx, int channel_id, struct sockaddr *remote_addrp, socklen_t remote_addrlen)
{
  int i,index;
  time_t now;

  strategy_info_t *info;

  if(channel_id >= ctx->strategys){
	errf("%s channel_id(%d) is bigger than max channel(%d)", __func__, channel_id, ctx->strategys);
	return;
  }

  show_addr(__func__, channel_id, remote_addrp, remote_addrlen);

  time(&now);

	info = &ctx->info[channel_id];
  // if already in list, update time and return
  for (i = 0; i < info->nknown_addr; i++) {
    if (remote_addrlen == info->known_addrs[i].addrlen) {
      if (0 == memcmp(remote_addrp, &info->known_addrs[i].addr,
                      remote_addrlen)) {
        info->known_addrs[i].last_recv_time = now;
		info->addr_mask |= 1<<i;
        return;
      }
    }
  }
  // if address list is not full, just append remote addr
  if (info->nknown_addr < ctx->addrs) {
    save_addr(&info->known_addrs[info->nknown_addr], remote_addrp,
              remote_addrlen, now);
	info->addr_mask |= 1<< info->nknown_addr;
    info->nknown_addr++;
    return;
  }
  // if full, replace the oldest
  addr_info_t *oldest_addr_info = NULL;
  for (i = 0; i < info->nknown_addr; i++) {
    if (oldest_addr_info == NULL ||
        oldest_addr_info->last_recv_time >
          info->known_addrs[i].last_recv_time) {
      oldest_addr_info = &info->known_addrs[i];
	  index = i;
    }
  }
  if (oldest_addr_info) {
    save_addr(oldest_addr_info, remote_addrp, remote_addrlen, now);
	info->addr_mask |= 1<<index;
  }
}

int strategy_choose_remote_addr(strategy_ctx_t *ctx, int *channel_id, struct sockaddr *remote_addrp, socklen_t *remote_addrlen)
{
	if(ctx->type == STRATEGY_RND)
		return strategy_choose_server_addr(ctx, channel_id, remote_addrp, remote_addrlen);
	else
		return strategy_choose_client_addr(ctx, channel_id, remote_addrp, remote_addrlen);
}


void strategy_update_remote_addr_list(strategy_ctx_t *ctx, int channel_id, struct sockaddr *remote_addrp, socklen_t remote_addrlen)
{
	if(ctx->type == STRATEGY_RND)
		strategy_update_server_addr_list(ctx, channel_id, remote_addrp, remote_addrlen);
	else
		strategy_update_client_addr_list(ctx, channel_id, remote_addrp, remote_addrlen);
}



