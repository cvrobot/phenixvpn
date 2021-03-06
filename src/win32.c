/**
  win32.c

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
/*
 * Windows TUN/TAP support from iodine
 * http://code.kryo.se/iodine/
 *
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "shadowvpn.h"
#include <winioctl.h>

#include <netioapi.h>

#include <iphlpapi.h>

typedef unsigned long in_addr_t;
struct tun_data {
  HANDLE tun;
  int sock;
  struct sockaddr addr;
  socklen_t addrlen;
};

#define TUN_READER_BUF_SIZE (64 * 1024)
#define TUN_NAME_BUF_SIZE 256

#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_CONFIG_TUN       TAP_CONTROL_CODE(10, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(6, METHOD_BUFFERED)

#define TAP_ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETWORK_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define TAP_DEVICE_SPACE "\\\\.\\Global\\"
#define TAP_VERSION_ID_0801 "tap0801"
#define TAP_VERSION_ID_0901 "tap0901"
#define KEY_COMPONENT_ID "ComponentId"
#define NET_CFG_INST_ID "NetCfgInstanceId"
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)

HANDLE dev_handle;
static struct tun_data data;
static char if_name[TUN_NAME_BUF_SIZE];

static void get_name(char *ifname, int namelen, char *dev_name);

static void get_device(char *device, int device_len, const char *wanted_dev) {
  LONG status;
  HKEY adapter_key;
  int index;

  index = 0;
  status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TAP_ADAPTER_KEY, 0, KEY_READ,
                        &adapter_key);

  if (status != ERROR_SUCCESS) {
    errf("Error opening registry key " TAP_ADAPTER_KEY );
    return;
  }

  while (TRUE) {
    char name[TUN_NAME_BUF_SIZE];
    char unit[TUN_NAME_BUF_SIZE];
    char component[TUN_NAME_BUF_SIZE];

    char cid_string[TUN_NAME_BUF_SIZE] = KEY_COMPONENT_ID;
    HKEY device_key;
    DWORD datatype;
    DWORD len;

    /* Iterate through all adapter of this kind */
    len = sizeof(name);
    status = RegEnumKeyEx(adapter_key, index, name, &len, NULL, NULL, NULL,
                          NULL);
    if (status == ERROR_NO_MORE_ITEMS) {
      break;
    } else if (status != ERROR_SUCCESS) {
      errf("Error enumerating subkeys of registry key " TAP_ADAPTER_KEY );
      break;
    }

    snprintf(unit, sizeof(unit), TAP_ADAPTER_KEY "\\%s", name);
    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, unit, 0, KEY_READ, &device_key);
    if (status != ERROR_SUCCESS) {
      errf("Error opening registry key %s", unit);
      goto next;
    }

    /* Check component id */
    len = sizeof(component);
    status = RegQueryValueEx(device_key, cid_string, NULL, &datatype,
                             (LPBYTE)component, &len);
    if (status != ERROR_SUCCESS || datatype != REG_SZ) {
      goto next;
    }
    if (strncmp(TAP_VERSION_ID_0801, component,
                strlen(TAP_VERSION_ID_0801)) == 0 ||
        strncmp(TAP_VERSION_ID_0901, component,
                strlen(TAP_VERSION_ID_0901)) == 0) {
      /* We found a TAP32 device, get its NetCfgInstanceId */
      char iid_string[TUN_NAME_BUF_SIZE] = NET_CFG_INST_ID;

      status = RegQueryValueEx(device_key, iid_string, NULL, &datatype,
                               (LPBYTE) device, (DWORD *) &device_len);
      if (status != ERROR_SUCCESS || datatype != REG_SZ) {
        errf("Error reading registry key %s\\%s on TAP device", unit,
             iid_string);
      } else {
        /* Done getting GUID of TAP device,
         * now check if the name is the requested one */
        if (wanted_dev) {
          char name[TUN_NAME_BUF_SIZE];
          get_name(name, sizeof(name), device);
          if (strncmp(name, wanted_dev, strlen(wanted_dev))) {
            /* Skip if name mismatch */
            goto next;
          }
        }
        /* Get the if name */
        get_name(if_name, sizeof(if_name), device);
        setenv("intf", if_name, 1);
        RegCloseKey(device_key);
        return;
      }
    }
next:
    RegCloseKey(device_key);
    index++;
  }
  RegCloseKey(adapter_key);
}

static void get_name(char *ifname, int namelen, char *dev_name) {
  char path[TUN_NAME_BUF_SIZE];
  char name_str[TUN_NAME_BUF_SIZE] = "Name";
  LONG status;
  HKEY conn_key;
  DWORD len;
  DWORD datatype;

  memset(ifname, 0, namelen);

  snprintf(path, sizeof(path), NETWORK_KEY "\\%s\\Connection", dev_name);
  status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &conn_key);
  if (status != ERROR_SUCCESS) {
    errf("could not look up name of interface %s: error opening key\n",
         dev_name);
    RegCloseKey(conn_key);
    return;
  }
  len = namelen;
  status = RegQueryValueEx(conn_key, name_str, NULL, &datatype, (LPBYTE)ifname,
                           &len);
  if (status != ERROR_SUCCESS || datatype != REG_SZ) {
    errf("could not look up name of interface %s: error reading value\n",
         dev_name);
    RegCloseKey(conn_key);
    return;
  }
  RegCloseKey(conn_key);
}

static int inet_aton(const char *cp, struct in_addr *inp) {
  inp->s_addr = inet_addr(cp);
  return inp->s_addr != INADDR_ANY;
}

static int tun_setip(const char *ip, int netbits) {
  int netmask;
  struct in_addr net;
  int i;
  int r;
  DWORD status;
  DWORD ipdata[3];
  struct in_addr addr;
  DWORD len;

  if (ip == NULL) {
    errf("missing tunip: win32 needs to specify tun ip");
    return -1;
  }

  netmask = 0;
  for (i = 0; i < netbits; i++) {
    netmask = (netmask << 1) | 1;
  }
  netmask <<= (32 - netbits);
  net.s_addr = htonl(netmask);

  if (inet_addr(ip) == INADDR_NONE) {
    errf("invalid tun ip: %s", ip);
    return -1;
  }

  /* Set device as connected */
  logf("enabling interface '%s'", if_name);
  status = 1;
  r = DeviceIoControl(dev_handle, TAP_IOCTL_SET_MEDIA_STATUS, &status,
      sizeof(status), &status, sizeof(status), &len, NULL);
  if (!r) {
    errf("failed to enable interface");
    return -1;
  }

  if (inet_aton(ip, &addr)) {
    ipdata[0] = (DWORD) addr.s_addr;   /* local ip addr */
    ipdata[1] = net.s_addr & ipdata[0]; /* network addr */
    ipdata[2] = (DWORD) net.s_addr;    /* netmask */
  } else {
    return -1;
  }

  /* Tell ip/networkaddr/netmask to device for arp use */
  r = DeviceIoControl(dev_handle, TAP_IOCTL_CONFIG_TUN, &ipdata,
      sizeof(ipdata), &ipdata, sizeof(ipdata), &len, NULL);
  if (!r) {
    errf("failed to set interface in tun mode");
    return -1;
  }

  return 0;
}

/*
 * Get adapter info list
 */
static IP_ADAPTER_INFO *get_adapter_info_list(void)
{
    ULONG size = 0;
    IP_ADAPTER_INFO *pi = NULL;
    DWORD status;

    if ((status = GetAdaptersInfo(NULL, &size)) != ERROR_BUFFER_OVERFLOW)
    {
        errf("GetAdaptersInfo #1 failed (status=%u)", (unsigned int)status);
    }
    else
    {
        pi = (PIP_ADAPTER_INFO) malloc(size);
        if ((status = GetAdaptersInfo(pi, &size)) == NO_ERROR)
        {
            return pi;
        }
        else
        {
            errf("GetAdaptersInfo #2 failed (status=%u)", (unsigned int)status);
        }
    }
    return pi;
}

/*
 * Get interface index for use with IP Helper API functions.
 */
static DWORD get_adapter_index_method_1(const char *guid)
{
    DWORD index;
    ULONG aindex;
    wchar_t wbuf[256];
    _snwprintf(wbuf, sizeof(wbuf), L"\\DEVICE\\TCPIP_%S", guid);
    wbuf [sizeof(wbuf) - 1] = 0;
    if (GetAdapterIndex(wbuf, &aindex) != NO_ERROR)
    {
        index = -1;
    }
    else
    {
        index = (DWORD)aindex;
    }
    return index;
}

static DWORD get_adapter_index_method_2(const char *guid)
{
    DWORD index = -1;

    IP_ADAPTER_INFO *list = get_adapter_info_list();

    while (list)
    {
        if (!strcmp(guid, list->AdapterName))
        {
            index = list->Index;
            break;
        }
        list = list->Next;
    }

	if(list)
	    free(list);
    return index;
}

static DWORD get_adapter_index(const char *guid)
{
    DWORD index;
    index = get_adapter_index_method_1(guid);
    if (index == -1)
    {
        index = get_adapter_index_method_2(guid);
    }
    if (index == -1)
    {
        errf("NOTE: could not get adapter index for %s", guid);
    }
    return index;
}

/*
 * Sets interface metric value for specified interface index.
 *
 * Arguments:
 *   index         : The index of TAP adapter.
 *   family        : Address family (AF_INET for IPv4 and AF_INET6 for IPv6).
 *   metric        : Metric value. 0 for automatic metric.
 * Returns 0 on success, a non-zero status code of the last failed action on failure.
 */

DWORD set_interface_metric(const NET_IFINDEX index, const ADDRESS_FAMILY family,
                     const ULONG metric)
{
    DWORD err = 0;
    MIB_IPINTERFACE_ROW ipiface;
    InitializeIpInterfaceEntry(&ipiface);
    ipiface.Family = family;
    ipiface.InterfaceIndex = index;
    err = GetIpInterfaceEntry(&ipiface);
    if (err == NO_ERROR)
    {
        if (family == AF_INET)
        {
            /* required for IPv4 as per MSDN */
            ipiface.SitePrefixLength = 0;
        }
        ipiface.Metric = metric;
        if (metric == 0)
        {
            ipiface.UseAutomaticMetric = TRUE;
        }
        else
        {
            ipiface.UseAutomaticMetric = FALSE;
        }
        err = SetIpInterfaceEntry(&ipiface);
        if (err == NO_ERROR)
        {
            return 0;
        }
    }
    return err;
}

static MIB_IPFORWARDTABLE *
get_windows_routing_table()
{
    ULONG size = 0;
    PMIB_IPFORWARDTABLE rt = NULL;
    DWORD status;

    status = GetIpForwardTable(NULL, &size, TRUE);
    if (status == ERROR_INSUFFICIENT_BUFFER)
    {
        rt = (PMIB_IPFORWARDTABLE) malloc(size);
        status = GetIpForwardTable(rt, &size, TRUE);
        if (status != NO_ERROR)
        {
            errf("NOTE: GetIpForwardTable returned error: %s (code=%u)",
                strerror(status),
                (unsigned int)status);
            rt = NULL;
        }
    }
    return rt;
}

static const MIB_IPFORWARDROW *
get_default_gateway_row(const MIB_IPFORWARDTABLE *routes)
{
    DWORD lowest_metric = MAXDWORD;
    const MIB_IPFORWARDROW *ret = NULL;
    int i;
    int best = -1;

    if (routes)
    {
        for (i = 0; i < routes->dwNumEntries; ++i)
        {
            const MIB_IPFORWARDROW *row = &routes->table[i];
            const in_addr_t net = ntohl(row->dwForwardDest);
            const in_addr_t mask = ntohl(row->dwForwardMask);
            const DWORD index = row->dwForwardIfIndex;
            const DWORD metric = row->dwForwardMetric1;
/*
            dmsg(D_ROUTE_DEBUG, "GDGR: route[%d] %s/%s i=%d m=%d",
                 i,
                 print_in_addr_t((in_addr_t) net, 0, &gc),
                 print_in_addr_t((in_addr_t) mask, 0, &gc),
                 (int)index,
                 (int)metric);
*/
            if (!net && !mask && metric < lowest_metric)
            {
                ret = row;
                lowest_metric = metric;
                best = i;
            }
        }
    }


    return ret;
}

void get_default_getway_intf_index()
{
	char id[2];

    MIB_IPFORWARDTABLE *routes = get_windows_routing_table();
    const MIB_IPFORWARDROW *row = get_default_gateway_row(routes);

	itoa(row->dwForwardIfIndex, id, 10);
	setenv("orig_intf_id", id, 1);
    errf("%s  %d", __func__, row->dwForwardIfIndex);
    free(routes);
}

DWORD WINAPI tun_reader(LPVOID arg) {
  struct tun_data *tun = arg;
  char buf[TUN_READER_BUF_SIZE];
  int len;
  int res;
  OVERLAPPED olpd;
  int sock;
  struct sockaddr addr;
  socklen_t addrlen;

  sock = channel_udp_alloc(1, TUN_DELEGATE_ADDR, 0, &addr, &addrlen);

  olpd.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

  while(TRUE) {
    olpd.Offset = 0;
    olpd.OffsetHigh = 0;
    res = ReadFile(tun->tun, buf, sizeof(buf), (LPDWORD) &len, &olpd);
    if (!res) {
      WaitForSingleObject(olpd.hEvent, INFINITE);
      res = GetOverlappedResult(dev_handle, &olpd, (LPDWORD) &len, FALSE);
      res = sendto(sock, buf, len, 0, &tun->addr, tun->addrlen);
    }
  }

  return 0;
}

int tun_open(const char *tun_device, const char*net_ip, int net_mask,
             int tun_port) {
  char adapter[TUN_NAME_BUF_SIZE];
  char tapfile[TUN_NAME_BUF_SIZE * 2];
  int tunfd;
  DWORD adapter_index;

  memset(adapter, 0, sizeof(adapter));
  memset(if_name, 0, sizeof(if_name));
  get_device(adapter, sizeof(adapter), tun_device);

  if (strlen(adapter) == 0 || strlen(if_name) == 0) {
    if (tun_device) {
      errf("no TAP adapters found");
    } else {
      errf("no TAP adapters found: version 0801 and 0901 are supported");
    }
    return -1;
  }

  logf("opening device %s\n", if_name);
  snprintf(tapfile, sizeof(tapfile), "%s%s.tap", TAP_DEVICE_SPACE, adapter);
  dev_handle = CreateFile(tapfile, GENERIC_WRITE | GENERIC_READ, 0, 0,
                          OPEN_EXISTING,
                          FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
  if (dev_handle == INVALID_HANDLE_VALUE) {
    errf("can not open device");
    return -1;
  }
  if (0 != tun_setip(net_ip, net_mask)) {
    errf("can not connect device");
    return -1;
  }
  
  adapter_index = get_adapter_index(adapter);
  if(adapter_index >= 0){
		char id[2];
		itoa(adapter_index, id, 10);
		setenv("intf_id", id, 1);
  	set_interface_metric(adapter_index,AF_INET,1);
  }else
  	errf("can not get adapter(%s) index: %d", adapter, adapter_index);

  get_default_getway_intf_index();//get default getway_intf_index, and set it to env

  /* Use a UDP connection to forward packets from tun,
   * so we can still use select() in main code.
   * A thread does blocking reads on tun device and
   * sends data as udp to this socket */

  tunfd = channel_udp_alloc(1, TUN_DELEGATE_ADDR, tun_port, &data.addr,
                        &data.addrlen);
  if (INVALID_SOCKET == tunfd) {
    errf("can not bind delegate port for tun: %d", tun_port);
    return -1;
  }

  data.tun = dev_handle;
  CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) tun_reader, &data, 0, NULL);
  return tunfd;
}

int setenv(const char *name, const char *value, int overwrite) {
  char envbuf[TUN_NAME_BUF_SIZE];
  snprintf(envbuf, sizeof(envbuf), "%s=%s", name, value);
  return _putenv(envbuf);
}

/*
 * disable new behavior using IOCTL: SIO_UDP_CONNRESET
 * Reference: http://support2.microsoft.com/kb/263823/en-us
 */
int disable_reset_report(int fd) {
  DWORD dwBytesReturned = 0;
  BOOL bNewBehavior = FALSE;
  if (INVALID_SOCKET == fd) {
    return -1;
  }
  if (SOCKET_ERROR == WSAIoctl(fd, SIO_UDP_CONNRESET,
                               &bNewBehavior, sizeof(bNewBehavior),
                               NULL, 0, &dwBytesReturned, NULL, NULL)) {
    errf("cannot disable UDP-Socket option SIO_UDP_CONNRESET");
    close(fd);
    return -1;
  }
  return fd;
}
