// Licensed under the Apache-2.0 license

/**
 * @file lwipopts.h
 * lwIP configuration for Rust bindings
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
*/
#define MEM_ALIGNMENT                   4
#define MEM_SIZE                        (16 * 1024)

#define MEMP_NUM_PBUF                   32
#define MEMP_NUM_UDP_PCB                8
#define MEMP_NUM_TCP_PCB                8
#define MEMP_NUM_TCP_PCB_LISTEN         4
#define MEMP_NUM_TCP_SEG                16
#define MEMP_NUM_NETBUF                 8
#define MEMP_NUM_NETCONN                8
#define MEMP_NUM_SYS_TIMEOUT            16

#define PBUF_POOL_SIZE                  32
#define PBUF_POOL_BUFSIZE               1536

/*
   ---------------------------------
   ---------- IP options ----------
   ---------------------------------
*/
#define LWIP_IPV4                       1
#define LWIP_IPV6                       1
#define LWIP_IPV6_DHCP6                 1
#define LWIP_IPV6_DHCP6_STATEFUL        1
#define IP_FORWARD                      0
#define IP_OPTIONS_ALLOWED              1
#define IP_REASSEMBLY                   1
#define IP_FRAG                         1
#define IP_REASS_MAXAGE                 3
#define IP_REASS_MAX_PBUFS              10
#define IP_DEFAULT_TTL                  64

/* IPv6 specific options */
#define LWIP_IPV6_AUTOCONFIG            1
#define LWIP_IPV6_MLD                   1
#define LWIP_ICMP6                      1
#define LWIP_IPV6_FRAG                  1
#define IPV6_FRAG_COPYHEADER            1
#define IPV6_REASS_MAXAGE               60
#define LWIP_ND6_TCP_REACHABILITY_HINTS 1
#define MEMP_NUM_ND6_QUEUE              8
#define LWIP_ND6_RETRANS_TIMER          1000
#define LWIP_ND6_DELAY_FIRST_PROBE_TIME 5000

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
#define LWIP_TCP                        1
#define TCP_TTL                         64
#define TCP_QUEUE_OOSEQ                 1
#define TCP_MSS                         1460
#define TCP_SND_BUF                     (4 * TCP_MSS)
#define TCP_SND_QUEUELEN                (4 * TCP_SND_BUF / TCP_MSS)
#define TCP_WND                         (4 * TCP_MSS)

/*
   -----------------------------------------
   ---------- ARP options ----------
   -----------------------------------------
*/
#define LWIP_ARP                        1
#define ARP_TABLE_SIZE                  10
#define ARP_QUEUEING                    1
#define ETHARP_SUPPORT_STATIC_ENTRIES   1

/*
   ------------------------------------
   ---------- TFTP options ----------
   ------------------------------------
*/
#define LWIP_TFTP                       1
#define TFTP_MAX_RETRIES                5
#define TFTP_TIMEOUT_MSECS              5000

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
#define TCP_DEBUG                       LWIP_DBG_OFF
#define DHCP_DEBUG                      LWIP_DBG_OFF
#define TFTP_DEBUG                      LWIP_DBG_OFF

/*
   ------------------------------------------
   ---------- Checksum options ----------
   ------------------------------------------
*/
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_GEN_TCP                1
#define CHECKSUM_GEN_ICMP               1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_UDP              1
#define CHECKSUM_CHECK_TCP              1
#define CHECKSUM_CHECK_ICMP             1

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
#define LWIP_NETIF_HOSTNAME             1
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
