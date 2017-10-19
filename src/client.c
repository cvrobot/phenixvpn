
#include "shadowvpn.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

//#include "uthash.h"
#include "portable_endian.h"

#ifndef TARGET_WIN32
#include <linux/ip.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

typedef struct iphdr ipv4_hdr_t;

int client_init(cli_ctx_t *ctx, shadowvpn_args_t *args)
{
  int i;
  bzero(ctx, sizeof(cli_ctx_t));
	//init ctx
	ctx->concurrency = args->concurrency;

	//add client
  for (i = 0; i < args->clients; i++) {
		client_add(ctx, htonl(args->netip + i + 1), args->password);
  }
	return 0;
}

int client_add(cli_ctx_t *ctx, uint32_t netip, const char *pwd)
{
	cli_info_t *cli = malloc(sizeof(cli_info_t));
	bzero(cli, sizeof(cli_info_t));

	cli->ctx = ctx;
	cli->known_addrs = calloc(ctx->concurrency, sizeof(addr_info_t));
	// assign IP based on tun IP and user tokens
	// for example:
	//		 tun IP is 10.7.0.1
	//		 client IPs will be 10.7.0.2, 10.7.0.3, 10.7.0.4, etc
	cli->output_tun_ip = netip;
	cli->pwd = strdup(pwd);
	struct in_addr in;
	in.s_addr = netip;
	logf("allocate output_tun_ip %s", inet_ntoa(in));
	// add to hash: ctx->ip_to_clients[output_tun_ip] = client
	HASH_ADD(hh, ctx->ip_to_clients, output_tun_ip, 4, cli);

	return 0;
}

cli_info_t *client_check_ip(cli_ctx_t *ctx, uint32_t netip)
{
	cli_info_t *cli = NULL;

	unsigned char ip[5] = {0};
	struct in_addr in;
	in.s_addr = netip;

	memcpy(ip, &netip,sizeof(netip));
	HASH_FIND(hh, ctx->ip_to_clients, ip, 4, cli);
	if (cli == NULL) {
		logf("nat: client not found for given netip:%s", inet_ntoa(in));
	}else{
		logf("nat: client found for given netip:%s", inet_ntoa(in));
	}
	return cli;
}


int client_check_add(cli_ctx_t *ctx, uint32_t netip, const char *pwd)
{
	if(client_check_ip(ctx, netip) == NULL){
		client_add(ctx, netip, pwd);
		return 0;
	}else{
		//TODO: client already exist.
		return -1;
	}
}

int client_remove(cli_ctx_t *ctx, uint32_t netip)
{
	cli_info_t *cli = client_check_ip(ctx, netip);
	if(cli != NULL){
		HASH_DELETE(hh, ctx->ip_to_clients, cli);
		free(cli->pwd);
		free(cli);
	}
	return 0;
}

//get client according to ipv4 head daddr
int get_client_by_ipaddr(cli_ctx_t *ctx, unsigned char *buf, size_t buflen, int is_saddr)
{
	ipv4_hdr_t *iphdr = (ipv4_hdr_t *)(buf);

	uint8_t iphdr_len;

	ctx->cli = NULL;
	if ((iphdr->version & 0xf) != 0x4) {
		// check header, currently IPv4 only
		// bypass IPv6
		logf("%s ipv6 not support version:0x%x", __func__, iphdr->version);
		return 0;
	}
	iphdr_len = (iphdr->version & 0x0f) * 4;

	if(is_saddr)
		HASH_FIND(hh, ctx->ip_to_clients, &iphdr->saddr, 4, ctx->cli);
	else
		HASH_FIND(hh, ctx->ip_to_clients, &iphdr->daddr, 4, ctx->cli);

	struct in_addr da,sa;
	da.s_addr = iphdr->daddr;
	sa.s_addr = iphdr->saddr;
	if (ctx->cli == NULL) {
		errf("nat: client not found for given addr token is_saddr:%d, saddr:%s,daddr:%s", is_saddr, inet_ntoa(sa),inet_ntoa(da));
		return -1;
	}
	logf("nat: client  found for given addr token is_saddr:%d, saddr:%s,daddr:%s", is_saddr, inet_ntoa(sa),inet_ntoa(da));
	return 0;
}

//get client according to ipv4 head daddr, used at down stream
int get_client_by_daddr(cli_ctx_t *ctx, unsigned char *buf, size_t buflen)
{
	return get_client_by_ipaddr(ctx, buf, buflen, 0);
}

//get client according to ipv4 head saddr, used at up stream
int get_client_by_saddr(cli_ctx_t *ctx, unsigned char *buf, size_t buflen)
{
	return get_client_by_ipaddr(ctx, buf, buflen, 1);
}
#else
int client_init(cli_ctx_t *ctx, shadowvpn_args_t *args)
{
	return 0;
}
int client_add(cli_ctx_t *ctx, uint32_t netip, const char* pwd)
{
	return 0;
}
cli_info_t *client_check_ip(cli_ctx_t *ctx, uint32_t netip)
{
	return NULL;
}
int client_check_add(cli_ctx_t *ctx, uint32_t netip, const char *pwd)
{
	return 0;
}
int client_remove(cli_ctx_t *ctx, uint32_t netip)
{
	return 0;
}
int get_client_by_ipaddr(cli_ctx_t *ctx, unsigned char *buf, size_t buflen, int is_saddr)
{
	return 0;
}
int get_client_by_daddr(cli_ctx_t *ctx, unsigned char *buf, size_t buflen)
{
	return 0;
}
int get_client_by_saddr(cli_ctx_t *ctx, unsigned char *buf, size_t buflen)
{
	return 0;
}
#endif

