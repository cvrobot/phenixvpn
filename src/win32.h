/**
  win32.h

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

#ifndef WIN32_H
#define WIN32_H

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif

#define _WIN32_WINNT 0x0501

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define bzero(...) ZeroMemory(__VA_ARGS__)
#define TUN_DELEGATE_ADDR "127.0.0.1"
#define TUN_DELEGATE_PORT 55151

extern HANDLE dev_handle;
typedef unsigned char __u8;
typedef unsigned short __be16;
typedef unsigned short __sum16;
typedef unsigned int __be32;

struct ipv6hdr {
	__u8			priority:4,
				version:4;
	__u8			flow_lbl[3];

	__be16			payload_len;
	__u8			nexthdr;
	__u8			hop_limit;

	struct	in6_addr	saddr;
	struct	in6_addr	daddr;
};

struct iphdr {
	__u8	ihl:4,
		version:4;

	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	/*The options start here. */
};

int tun_open(const char *tun_device, const char *net_ip, int net_mask, int tun_port);
int setenv(const char *name, const char *value, int overwrite);
int disable_reset_report(int fd);

#endif
