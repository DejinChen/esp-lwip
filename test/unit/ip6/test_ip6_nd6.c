#include "test_ip6_nd6.h"

#include "lwip/ethip6.h"
#include "lwip/icmp6.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/prot/ip6.h"
#include "lwip/prot/nd6.h"
#include "lwip/tcpip.h"
#include "lwip/udp.h"
#include "netif/ethernet.h"

#if LWIP_IPV6 && LWIP_ND6

static struct netif host_netif;
static struct netif router_netif;
static u8_t router_mac[6] = {1, 2, 3, 4, 5, 6};

/* Setups/teardown functions */
static void ip6nd6_setup(void) {
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static void ip6nd6_teardown(void) {
  if (netif_list->loop_first != NULL) {
    pbuf_free(netif_list->loop_first);
    netif_list->loop_first = NULL;
  }
  netif_list->loop_last = NULL;
  tcpip_thread_poll_one();
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static err_t router_tx_func(struct netif *netif, struct pbuf *p) {
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(p);
  return ERR_OK;
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

static err_t testif_init_router(struct netif *netif) {
  netif->name[0] = 't';
  netif->name[1] = 'r';
  netif->linkoutput = router_tx_func;
  netif->output_ip6 = ethip6_output;
  netif->mtu = 1500;
  netif->hwaddr_len = ETH_HWADDR_LEN;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHERNET | NETIF_FLAG_MLD6;

  memcpy(netif->hwaddr, router_mac, 6);
  return ERR_OK;
}

/* Test functions */
START_TEST(test_ip6_nd6_ra_rio) {
  /* struct pbuf *ra_rio_pbuf = NULL; */
  /*
  err_t err = ERR_OK;
  const u8_t *hwaddr = NULL;
  */
  /* struct netif *found_route = NULL; */
  ip6_addr_t router_addr, host_addr, dst_addr, rio_prefix, multicast_addr;
  s8_t chosen_idx = -1;

  netif_add(&router_netif, NULL, NULL, NULL, NULL, testif_init_router,
            ethernet_input);

  netif_set_default(&router_netif);

  ip6addr_aton("fe80::ab00:beef:cafe:1", &router_addr);
  netif_add_ip6_address(&router_netif, &router_addr, &chosen_idx);
  fail_unless(chosen_idx != -1);
  router_netif.ip6_addr_state[chosen_idx] = IP6_ADDR_VALID;

  ip6addr_aton("fe80::ab00:beef:cafe:3", &host_addr);
  chosen_idx = -1;

  netif_set_up(&router_netif);
  /* netif_set_up(&host_netif); */

  ip6addr_aton("ff02::1", &multicast_addr);
  ip6addr_aton("fdde:ad00:beef:cafe::", &rio_prefix);
  ip6addr_aton("fdde:ad00:beef:cafe::1", &dst_addr);

  /* Check the route before receiving the ra_rio packet */
  /* found_route = nd6_find_route(&dst_addr);
  fail_unless(found_route == NULL); */

  /* Send ra_rio packet */
  /*
  ra_rio_pbuf = create_nd6_rio_test_packet(&multicast_addr, &router_addr,
                                           &rio_prefix, &router_mac[0]);
  fail_unless(ra_rio_pbuf != NULL);
  send_to_netif(&host_netif, ra_rio_pbuf); */

  /* call nd6_tmr() to clean the invalid default router */
  printf("call nd6_tmr: netif:%p\r\n", (void *)&router_netif);
  router_netif.rs_count = 0;
  host_netif.rs_count = 0;
  nd6_tmr();

  /* Check the route after receiving the ra_rio packet */
  /*
  found_route = nd6_find_route(&dst_addr);
  fail_unless(found_route == &host_netif);
  */

  /* Check next hop */
  /*
  err = nd6_get_next_hop_addr_or_queue(found_route, NULL, &dst_addr, &hwaddr);
  fail_unless(err == ERR_OK);
  fail_unless(hwaddr != NULL);
  fail_unless(memcmp(router_mac, hwaddr, 6) == 0);
  */

  /* cleanup */
  netif_set_down(&router_netif);
  netif_remove(&router_netif);
  /* netif_set_down(&host_netif);
  netif_remove(&host_netif); */
  /* ra_rio_pbuf = NULL; */
}
END_TEST

/** Create the suite including all tests for this module */
Suite *ip6_nd6_suite(void) {
  testfunc tests[] = {
      TESTFUNC(test_ip6_nd6_ra_rio),
  };
  return create_suite("IP6_ND6", tests, sizeof(tests) / sizeof(testfunc),
                      ip6nd6_setup, ip6nd6_teardown);
}
#endif /* LWIP_IPV6 && LWIP_ND6 */
