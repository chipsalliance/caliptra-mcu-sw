// Licensed under the Apache-2.0 license

/**
 * Wrapper header for bindgen - includes all lwIP headers we want to expose
 */

#ifndef LWIP_RS_WRAPPER_H
#define LWIP_RS_WRAPPER_H

/* Core lwIP */
#include "lwip/init.h"
#include "lwip/timeouts.h"
#include "lwip/err.h"
#include "lwip/pbuf.h"
#include "lwip/mem.h"
#include "lwip/memp.h"

/* Network interface */
#include "lwip/netif.h"
#include "netif/ethernet.h"
#include "netif/etharp.h"
#include "lwip/ethip6.h"

/* IPv4 */
#include "lwip/ip4_addr.h"
#include "lwip/ip4.h"
#include "lwip/icmp.h"

/* IPv6 */
#include "lwip/ip6_addr.h"
#include "lwip/ip6.h"
#include "lwip/icmp6.h"
#include "lwip/nd6.h"

/* DHCP */
#include "lwip/dhcp.h"
#include "lwip/dhcp6.h"

/* UDP/TCP */
#include "lwip/udp.h"
#include "lwip/tcp.h"

/* TFTP */
#include "lwip/apps/tftp_client.h"
#include "lwip/apps/tftp_common.h"

/* TAP interface (Unix port) */
#include "netif/tapif.h"

#endif /* LWIP_RS_WRAPPER_H */
