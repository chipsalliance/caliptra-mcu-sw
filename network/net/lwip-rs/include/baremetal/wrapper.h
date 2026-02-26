// Licensed under the Apache-2.0 license

/**
 * Wrapper header for bindgen - bare-metal version
 * Excludes TAP interface and other host-specific headers.
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

/* IPv4 */
#include "lwip/ip4_addr.h"
#include "lwip/ip4.h"
#include "lwip/icmp.h"

/* DHCP */
#include "lwip/dhcp.h"

/* UDP */
#include "lwip/udp.h"

/* TFTP (when enabled) */
#ifdef LWIP_BAREMETAL_TFTP
#include "lwip/apps/tftp_client.h"
#include "lwip/apps/tftp_common.h"
#endif

/* IPv6 (when enabled) */
#ifdef LWIP_BAREMETAL_IPV6
#include "lwip/ip6_addr.h"
#include "lwip/ip6.h"
#include "lwip/icmp6.h"
#include "lwip/nd6.h"
#include "lwip/dhcp6.h"
#include "lwip/ethip6.h"
#endif /* LWIP_BAREMETAL_IPV6 */

#endif /* LWIP_RS_WRAPPER_H */
