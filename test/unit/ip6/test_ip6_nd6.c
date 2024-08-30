#include "test_ip6_nd6.h"

#include "lwip/icmp6.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/prot/ip6.h"
#include "lwip/tcpip.h"
#include "lwip/udp.h"
#include "netif/ethernet.h"

#if LWIP_IPV6 && LWIP_ND6

static struct netif host_netif;
static struct netif router_netif;

/* Setups/teardown functions */
static void ip6nd6_setup(void) {
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static void ip6nd6_teardown(void) {
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

/* test helper functions */
/* static void debug_print_packet(struct pbuf *q) {
  struct ip_hdr *iphdr = (struct ip_hdr *)q->payload;
  u16_t iphdr_hlen;

  iphdr_hlen = IPH_HL_BYTES(iphdr);
  fail_unless(0 == inet_chksum((struct ip_hdr *)q->payload, iphdr_hlen));

  ip4_debug_print(q);

  last_src_addr = iphdr->src.addr;
  last_dst_addr = iphdr->dest.addr;

  if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
    struct udp_hdr *udphdr = (struct udp_hdr *)((u8_t *)iphdr + iphdr_hlen);
    udp_debug_print(udphdr);
    LWIP_DEBUGF(UDP_DEBUG, ("udp ("));
    ip_addr_debug_print_val(UDP_DEBUG, *ip_current_dest_addr());
    LWIP_DEBUGF(UDP_DEBUG, (", %" U16_F ") <-- (", lwip_ntohs(udphdr->dest)));
    ip_addr_debug_print_val(UDP_DEBUG, *ip_current_src_addr());
    LWIP_DEBUGF(UDP_DEBUG, (", %" U16_F ")\n", lwip_ntohs(udphdr->src)));
    last_src_port = udphdr->src;
  } else if (IPH_PROTO(iphdr) == IP_PROTO_TCP) {
    struct tcp_hdr *tcphdr;
    pbuf_header(q, -(s16_t)sizeof(struct ip_hdr));
    tcphdr = (struct tcp_hdr *)q->payload;
    tcp_debug_print(tcphdr);
    last_src_port = tcphdr->src;
  }
}
*/

static err_t router_output(struct netif *netif, struct pbuf *q,
                           const ip4_addr_t *ipaddr) {
  LWIP_PLATFORM_DIAG(("router output\n"));
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(q);
  LWIP_UNUSED_ARG(ipaddr);
  return ERR_OK;
}

static err_t host_output(struct netif *netif, struct pbuf *q,
                         const ip4_addr_t *ipaddr) {
  LWIP_PLATFORM_DIAG(("host output\n"));
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(q);
  LWIP_UNUSED_ARG(ipaddr);
  return ERR_OK;
}

static err_t host_tx_func(struct netif *netif, struct pbuf *p) {
  LWIP_PLATFORM_DIAG(("host tx\n"));
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(p);
  return ERR_OK;
}

static err_t router_tx_func(struct netif *netif, struct pbuf *p) {
  LWIP_PLATFORM_DIAG(("router tx\n"));
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(p);
  return ERR_OK;
}

static struct pbuf *create_nd6_rio_test_packet(ip_addr_t *dst_addr,
                                               ip_addr_t *src_addr) {

  struct pbuf *p;
  struct ip6_hdr *ip6hdr;
  struct icmp6_hdr *icmp6hdr;
  u8_t *ra_payload;
  u32_t route_lifetime;
  ip6_addr_t rio_prefix;

  p = pbuf_alloc(PBUF_IP,
                 sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + 8 + 24,
                 PBUF_RAM);
  fail_unless(p != NULL);
  if (p == NULL) {
    return NULL;
  }

  ip6hdr = (struct ip6_hdr *)p->payload;
  ip6hdr->_v_tc_fl = lwip_htonl((6 << 28) | (0));
  ip6hdr->_plen = lwip_htons(sizeof(struct icmp6_hdr) + 8 + 24);
  ip6hdr->_nexth = IP6_NEXTH_ICMP6;
  ip6hdr->_hoplim = 255;
  ip6_addr_copy_to_packed(ip6hdr->src, *ip_2_ip6(src_addr));
  ip6_addr_copy_to_packed(ip6hdr->dest, *ip_2_ip6(dst_addr));

  icmp6hdr = (struct icmp6_hdr *)((u8_t *)ip6hdr + sizeof(struct ip6_hdr));
  icmp6hdr->type = ICMP6_TYPE_RA;
  icmp6hdr->code = 0;
  icmp6hdr->chksum = 0;

  ra_payload = (u8_t *)(icmp6hdr + 4);
  ra_payload[0] = 64;                    /* Cur Hop Limit */
  ra_payload[1] = 0;                     /* M|O|H|Prf|Resvd */
  ra_payload[2] = lwip_htons(1800) >> 8; /* Router Lifetime */
  ra_payload[3] = lwip_htons(1800) & 0xFF;
  ra_payload[4] = 0; /* Reachable Time */
  ra_payload[5] = 0;
  ra_payload[6] = 0;
  ra_payload[7] = 0;
  ra_payload[8] = 0; /* Retrans Timer */
  ra_payload[9] = 0;
  ra_payload[10] = 0;
  ra_payload[11] = 0;

  ra_payload[12] = 24; /* Option Type: Route Information */
  ra_payload[13] = 3;  /* Option Length */
  ra_payload[18] = 64; /* Prefix Length */
  ra_payload[19] = 0;  /* Resvd|Prf|Resvd */

  route_lifetime = lwip_htonl(3600); /* Route Lifetime */
  memcpy(&ra_payload[20], &route_lifetime, sizeof(route_lifetime));

  IP6_ADDR(&rio_prefix, PP_HTONL(0x20010db8), 0, 0, 0); /* Route Prefix */
  memcpy(&ra_payload[24], &rio_prefix.addr[0], 16);

  icmp6hdr->chksum = ip6_chksum_pseudo_partial(
      p, IP6_NEXTH_ICMP6, p->tot_len, sizeof(icmp6hdr->chksum),
      ip_2_ip6(src_addr), ip_2_ip6(dst_addr));

  return p;
}

/*
static void send_to_netif(struct netif *input_netif, struct pbuf *p) {
  err_t err;

  if (p != NULL) {
    err = ip6_input(p, input_netif);
    fail_unless(err == ERR_OK);
  }
}
*/

static err_t testif_init_host(struct netif *netif) {
  netif->name[0] = 'h';
  netif->name[1] = 's';
  netif->output = host_output;
  netif->linkoutput = host_tx_func;
  netif->mtu = 1500;
  netif->hwaddr_len = ETH_HWADDR_LEN;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHERNET | NETIF_FLAG_MLD6 |
                 NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

  netif->hwaddr[0] = 0x01;
  netif->hwaddr[1] = 0x02;
  netif->hwaddr[2] = 0x03;
  netif->hwaddr[3] = 0x04;
  netif->hwaddr[4] = 0x05;
  netif->hwaddr[5] = 0x06;

  return ERR_OK;
}

static err_t testif_init_router(struct netif *netif) {
  netif->name[0] = 'r';
  netif->name[1] = 't';
  netif->output = router_output;
  netif->linkoutput = router_tx_func;
  netif->mtu = 1500;
  netif->hwaddr_len = ETH_HWADDR_LEN;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHERNET | NETIF_FLAG_MLD6 |
                 NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

  netif->hwaddr[0] = 0x01;
  netif->hwaddr[1] = 0x02;
  netif->hwaddr[2] = 0x03;
  netif->hwaddr[3] = 0x04;
  netif->hwaddr[4] = 0x05;
  netif->hwaddr[5] = 0x07;

  return ERR_OK;
}

/* Test functions */
START_TEST(test_ip6_nd6_ra_rio) {
  ip_addr_t my_addr = IPADDR6_INIT_HOST(0x20010db8, 0x0, 0x0, 0x1);
  ip_addr_t peer_addr = IPADDR6_INIT_HOST(0x20010db8, 0x0, 0x0, 0x4);
  ip4_addr_t addr1, addr2;
  struct pbuf *p;
  ip4_addr_t netmask;
  ip4_addr_t gw;
  err_t err;
  LWIP_UNUSED_ARG(_i);

  IP4_ADDR(&addr1, 1, 2, 3, 4);
  IP4_ADDR(&netmask, 255, 255, 255, 0);
  IP4_ADDR(&gw, 1, 2, 3, 4);

  netif_add(&router_netif, NULL, NULL, NULL, &router_netif, testif_init_router,
            ethernet_input);
  netif_ip6_addr_set(&router_netif, 0, ip_2_ip6(&my_addr));
  netif_ip6_addr_set_state(&router_netif, 0, IP6_ADDR_VALID);
  /* IP_ADDR6_HOST(&router_netif.ip6_addr[0], 0x2001db88, 0, 0, 1);
  router_netif.ip6_addr_state[0] = IP6_ADDR_VALID;
  IP_ADDR6_HOST(&router_netif.ip6_addr[1], 0x100288bd, 0, 0, 1);
  router_netif.ip6_addr_state[1] = IP6_ADDR_VALID;
  netif_create_ip6_linklocal_address(&router_netif, 1);
  netif_set_link_up(&router_netif); */
  netif_set_up(&router_netif);

  IP4_ADDR(&addr2, 1, 2, 3, 5);
  netif_add(&host_netif, NULL, NULL, NULL, &router_netif, testif_init_host,
            ethernet_input);
  netif_ip6_addr_set(&host_netif, 0, ip_2_ip6(&peer_addr));
  netif_ip6_addr_set_state(&host_netif, 0, IP6_ADDR_VALID);
  /*
  IP_ADDR6_HOST(&host_netif.ip6_addr[0], 0x2001db88, 0, 0, 2);
  host_netif.ip6_addr_state[0] = IP6_ADDR_VALID;
  netif_set_link_up(&host_netif);
  */
  netif_set_up(&host_netif);

  p = create_nd6_rio_test_packet(&peer_addr, &my_addr);
  /* send_to_netif(&host_netif, p); */
  err = ip6_output_if(p, ip_2_ip6(&my_addr), ip_2_ip6(&peer_addr), 255, 0,
                      IP_PROTO_ICMP, &router_netif);
  printf("Debug error :%d\n", err);
  LWIP_DEBUGF(UDP_DEBUG, ("Debug err: %d\n", err));
  LWIP_PLATFORM_DIAG(("ip6_output_if_src\n"));
  fail_unless(err == ERR_OK);

  /* cleanup */
  netif_set_down(&router_netif);
  netif_remove(&router_netif);
  netif_set_down(&host_netif);
  netif_remove(&host_netif);
  pbuf_free(p);
}
END_TEST

/** Create the suite including all tests for this module */
Suite *ip6_nd6_suite(void) {
  testfunc tests[] = {
      TESTFUNC(test_ip6_nd6_ra_rio),
  };
  return create_suite("IP6_ND6_RA_RIO", tests, sizeof(tests) / sizeof(testfunc),
                      ip6nd6_setup, ip6nd6_teardown);
}
#endif /* LWIP_IPV6 && LWIP_ND6 */
