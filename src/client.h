#ifndef CLIENT_H
#define CLIENT_H

#ifdef TARGET_WIN32
#include "win32.h"
#else
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include "uthash.h"

/* the structure to store known client addresses for the server */
typedef struct {
  struct sockaddr_storage addr;
  socklen_t addrlen;
  time_t last_recv_time;
} addr_info_t;

struct cli_ctx_t;

typedef struct {
  /* known client addrs for the server */
  int nknown_addr;
  addr_info_t *known_addrs;

	char *pwd;
	unsigned char *key;

  // input tun IP
  // in network order
  // TODO support IPv6 address on tun
  uint32_t input_tun_ip;

  // output tun IP
  // in network order
  uint32_t output_tun_ip;

  UT_hash_handle hh;

	struct cli_ctx_t *ctx;
}cli_info_t;

typedef struct cli_ctx_t{
	uint16_t concurrency;

	cli_info_t *cli;
  /* clients map
   TODO: use index instead of hash
   key: IP */
  cli_info_t *ip_to_clients;
} cli_ctx_t;

cli_ctx_t *client_init(shadowvpn_args_t *args);
int client_add(cli_ctx_t *ctx, uint32_t netip, const char* pwd);
cli_info_t *client_check_ip(cli_ctx_t *ctx, uint32_t netip);
int client_check_add(cli_ctx_t *ctx, uint32_t netip, const char *pwd);
int client_remove(cli_ctx_t *ctx, uint32_t netip);
int get_client_by_ipaddr(cli_ctx_t *ctx, unsigned char *buf, size_t buflen, int is_saddr);
int get_client_by_daddr(cli_ctx_t *ctx, unsigned char *buf, size_t buflen);
int get_client_by_saddr(cli_ctx_t *ctx, unsigned char *buf, size_t buflen);

#endif
