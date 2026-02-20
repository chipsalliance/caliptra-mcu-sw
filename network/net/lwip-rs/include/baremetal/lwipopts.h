// Licensed under the Apache-2.0 license

/**
 * @file lwipopts.h
 * lwIP configuration for bare-metal RISC-V firmware
 *
 * Tuned for minimal memory usage while supporting DHCP discovery.
 */

#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

#include "lwip/debug.h"

/*
   -----------------------------------------------
   ---------- Platform specific locking ----------
   -----------------------------------------------
*/
#define SYS_LIGHTWEIGHT_PROT            1
#define NO_SYS                          1
#define LWIP_TIMERS                     1
#define LWIP_TIMERS_CUSTOM              0

/*
   ------------------------------------
   ---------- Memory options ----------
   ------------------------------------
   Reduced for bare-metal with limited DCCM.
*/
#define MEM_ALIGNMENT                   4
#ifdef LWIP_BAREMETAL_IPV6
#define MEM_SIZE                        (4 * 1024)
#else
#define MEM_SIZE                        (4 * 1024)
#endif

#define MEMP_NUM_PBUF                   4
#define MEMP_NUM_UDP_PCB                2
#define MEMP_NUM_TCP_PCB                0
#define MEMP_NUM_TCP_PCB_LISTEN         0
#define MEMP_NUM_TCP_SEG                0
#define MEMP_NUM_NETBUF                 0
#define MEMP_NUM_NETCONN                0
#ifdef LWIP_BAREMETAL_IPV6
#define MEMP_NUM_SYS_TIMEOUT            12
#else
#define MEMP_NUM_SYS_TIMEOUT            8
#endif

#ifdef LWIP_BAREMETAL_IPV6
#define PBUF_POOL_SIZE                  6
#else
#define PBUF_POOL_SIZE                  8
#endif
#define PBUF_POOL_BUFSIZE               1024

/*
   ---------------------------------
   ---------- IP options ----------
   ---------------------------------
*/
#define LWIP_IPV4                       1
#ifdef LWIP_BAREMETAL_IPV6
#define LWIP_IPV6                       1
#else
#define LWIP_IPV6                       0
#endif
#define IP_FORWARD                      0
#define IP_OPTIONS_ALLOWED              1
#define IP_REASSEMBLY                   0
#define IP_FRAG                         0
#define IP_DEFAULT_TTL                  64

/*
   ----------------------------------
   ---------- ICMP options ----------
   ----------------------------------
*/
#define LWIP_ICMP                       1
#define ICMP_TTL                        64

/*
   ----------------------------------
   ---------- DHCP options ----------
   ----------------------------------
*/
#define LWIP_DHCP                       1
#define DHCP_DOES_ARP_CHECK             0
#define LWIP_DHCP_BOOTP_FILE            1
#define LWIP_DHCP_GET_NTP_SRV           0

/*
   ----------------------------------
   ---------- IPv6 options ----------
   ----------------------------------
*/
#ifdef LWIP_BAREMETAL_IPV6
#define LWIP_IPV6_NUM_ADDRESSES         3
#define LWIP_IPV6_DHCP6                 1
#define LWIP_IPV6_DHCP6_STATEFUL        0
#define LWIP_IPV6_AUTOCONFIG            1
#define LWIP_IPV6_FORWARD               0
#define LWIP_ICMP6                      1
#define LWIP_IPV6_MLD                   1
#define LWIP_IPV6_FRAG                  0
#define LWIP_IPV6_REASS                 0
#define LWIP_ND6_ALLOW_RA_UPDATES       1
#define LWIP_ND6_TCP_REACHABILITY_HINTS 0
#define LWIP_ND6_NUM_NEIGHBORS          4
#define LWIP_ND6_NUM_DESTINATIONS       4
#define LWIP_ND6_NUM_PREFIXES           2
#define LWIP_ND6_NUM_ROUTERS            1
#define MEMP_NUM_MLD6_GROUP             2
#define MEMP_NUM_ND6_QUEUE              2
#endif /* LWIP_BAREMETAL_IPV6 */

/*
   ---------------------------------
   ---------- UDP options ----------
   ---------------------------------
*/
#define LWIP_UDP                        1
#define UDP_TTL                         64

/*
   ---------------------------------
   ---------- TCP options ----------
   ---------------------------------
*/
#define LWIP_TCP                        0

/*
   -----------------------------------------
   ---------- ARP options ----------
   -----------------------------------------
*/
#define LWIP_ARP                        1
#define ARP_TABLE_SIZE                  4
#define ARP_QUEUEING                    1
#define ETHARP_SUPPORT_STATIC_ENTRIES   0

/*
   ------------------------------------
   ---------- TFTP options ----------
   ------------------------------------
*/
#define LWIP_TFTP                       0

/*
   ----------------------------------------
   ---------- Statistics options ----------
   ----------------------------------------
*/
#define LWIP_STATS                      0
#define LWIP_STATS_DISPLAY              0

/*
   ---------------------------------------
   ---------- Debugging options ----------
   ---------------------------------------
*/
#define LWIP_DEBUG                      0

#define ETHARP_DEBUG                    LWIP_DBG_OFF
#define NETIF_DEBUG                     LWIP_DBG_OFF
#define PBUF_DEBUG                      LWIP_DBG_OFF
#define ICMP_DEBUG                      LWIP_DBG_OFF
#define IP_DEBUG                        LWIP_DBG_OFF
#define UDP_DEBUG                       LWIP_DBG_OFF
#define DHCP_DEBUG                      LWIP_DBG_OFF
#ifdef LWIP_BAREMETAL_IPV6
#define DHCP6_DEBUG                     LWIP_DBG_OFF
#define IP6_DEBUG                       LWIP_DBG_OFF
#define ICMP6_DEBUG                     LWIP_DBG_OFF
#define ND6_DEBUG                       LWIP_DBG_OFF
#endif

/*
   ------------------------------------------
   ---------- Checksum options ----------
   ------------------------------------------
*/
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_GEN_TCP                0
#define CHECKSUM_GEN_ICMP               1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_UDP              1
#define CHECKSUM_CHECK_TCP              0
#define CHECKSUM_CHECK_ICMP             1
#ifdef LWIP_BAREMETAL_IPV6
#define CHECKSUM_GEN_ICMP6              1
#define CHECKSUM_CHECK_ICMP6            1
#endif

/*
   ----------------------------------------------
   ---------- Sequential API options ----------
   ----------------------------------------------
*/
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0

/*
   ------------------------------------
   ---------- NETIF options ----------
   ------------------------------------
*/
#define LWIP_NETIF_STATUS_CALLBACK      1
#define LWIP_NETIF_LINK_CALLBACK        1
#define LWIP_NETIF_HOSTNAME             0
#define LWIP_NETIF_API                  0
#define LWIP_NETIF_TX_SINGLE_PBUF       1

/*
   ----------------------------------------
   ---------- Misc options ----------
   ----------------------------------------
*/
#define LWIP_HAVE_LOOPIF                0
#define LWIP_LOOPBACK_MAX_PBUFS         0
#define LWIP_SINGLE_NETIF               1
#define LWIP_PROVIDE_ERRNO              1
#define LWIP_ETHERNET                   1
#define ETH_PAD_SIZE                    0

/* Platform-specific assertion macro */
void lwip_platform_assert(const char *msg, int line, const char *file);
#ifndef LWIP_PLATFORM_ASSERT
#define LWIP_PLATFORM_ASSERT(x) lwip_platform_assert(x, __LINE__, __FILE__)
#endif

#endif /* LWIP_LWIPOPTS_H */
