/*
  Copyright (C) 2016 Eneo Tecnologia S.L.
  Author: Eugenio Perez <eupm90@gmail.com>
  Based on Luca Deri nprobe 6.22 collector

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as
  published by the Free Software Foundation, either version 3 of the
  License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "f2k.h"

#include "rb_netflow_test.h"

#include <setjmp.h>
#include <cmocka.h>

#define TEST_TEMPLATE_ID_V4 512
#define TEST_TEMPLATE_ID_V6 513

#define TEST_FLOW_HEADER                                                       \
  .unix_secs = constexpr_be32toh(3713886546),                                  \
  .flow_sequence = constexpr_be32toh(232117909), .observation_id = 65536

#define FIXED_FLOW_ENTITIES(X)                                                 \
  X(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713))                             \
  X(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443))                               \
  X(IN_SRC_MAC, 6, 0, 0x00, 0x24, 0x14, 0x01, 0x02, 0x03)                      \
  X(IN_DST_MAC, 6, 0, 0x00, 0x22, 0x55, 0x04, 0x05, 0x06)                      \
  X(OUT_DST_MAC, 6, 0, 0x00, 0x24, 0x1d, 0x04, 0x05, 0x06)                     \
  X(PROTOCOL, 1, 0, 0x06)                                                      \
  X(FLOW_END_REASON, 1, 0, 0x03)                                               \
  X(BIFLOW_DIRECTION, 1, 0, 0x01)                                              \
  X(TRANSACTION_ID, 8, 0, 0x8f, 0x63, 0xf3, 0x40, 0x00, 0x01, 0x00, 0x00)      \
  X(FLOW_SAMPLER_ID, 1, 0, 0x00)                                               \
  X(APPLICATION_ID, 4, 0, 0x03, 0x00, 0x00, 0x50)                              \
  X(IN_BYTES, 8, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xb8)            \
  X(IN_PKTS, 4, 0, 0x00, 0x00, 0x00, 0x1f)                                     \
  X(FIRST_SWITCHED, 4, 0, 0x0f, 0xed, 0x0a, 0xc0)                              \
  X(LAST_SWITCHED, 4, 0, 0x0f, 0xee, 0x18, 0x00)

#define FIXED_FLOW_ENTITIES_1_V4(X)                                            \
  FIXED_FLOW_ENTITIES(X)                                                       \
  X(IPV4_SRC_ADDR, 4, 0, 10, 13, 30, 44)                                       \
  X(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19)                                     \
  X(IP_PROTOCOL_VERSION, 1, 0, 0x04)
#define FIXED_FLOW_ENTITIES_2_V4(X)                                            \
  FIXED_FLOW_ENTITIES(X)                                                       \
  X(IPV4_SRC_ADDR, 4, 0, 66, 220, 152, 19)                                     \
  X(IPV4_DST_ADDR, 4, 0, 10, 13, 30, 44)                                       \
  X(IP_PROTOCOL_VERSION, 1, 0, 0x04)
#define FIXED_FLOW_ENTITIES_3_V4(X)                                            \
  FIXED_FLOW_ENTITIES(X)                                                       \
  X(IPV4_SRC_ADDR, 4, 0, 10, 13, 30, 44)                                       \
  X(IPV4_DST_ADDR, 4, 0, 10, 13, 30, 45)                                       \
  X(IP_PROTOCOL_VERSION, 1, 0, 0x04)
#define FIXED_FLOW_ENTITIES_4_V4(X)                                            \
  FIXED_FLOW_ENTITIES(X)                                                       \
  X(IPV4_SRC_ADDR, 4, 0, 66, 220, 152, 19)                                     \
  X(IPV4_SRC_ADDR, 4, 0, 66, 220, 152, 20)                                     \
  X(IP_PROTOCOL_VERSION, 1, 0, 0x04)

#define FIXED_FLOW_ENTITIES_1_V6(X)                                            \
  FIXED_FLOW_ENTITIES(X)                                                       \
  X(IPV6_SRC_ADDR, 16, 0, 0x20, 0x01, 0x04, 0x28, 0xce, 0x00, 0x00, 0x00,      \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)                            \
  X(IPV6_DST_ADDR, 16, 0, 0x20, 0x01, 0x04, 0x28, 0xff, 0x00, 0x00, 0x00,      \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02)                            \
  X(IP_PROTOCOL_VERSION, 1, 0, 0x06)
#define FIXED_FLOW_ENTITIES_2_V6(X)                                            \
  FIXED_FLOW_ENTITIES(X)                                                       \
  X(IPV6_SRC_ADDR, 16, 0, 0x20, 0x01, 0x04, 0x28, 0xff, 0x00, 0x00, 0x00,      \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02)                            \
  X(IPV6_DST_ADDR, 16, 0, 0x20, 0x01, 0x04, 0x28, 0xce, 0x00, 0x00, 0x00,      \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)                            \
  X(IP_PROTOCOL_VERSION, 1, 0, 0x06)
#define FIXED_FLOW_ENTITIES_3_V6(X)                                            \
  FIXED_FLOW_ENTITIES(X)                                                       \
  X(IPV6_SRC_ADDR, 16, 0, 0x20, 0x01, 0x04, 0x28, 0xce, 0x00, 0x00, 0x00,      \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)                            \
  X(IPV6_DST_ADDR, 16, 0, 0x20, 0x01, 0x04, 0x28, 0xce, 0x00, 0x00, 0x00,      \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02)                            \
  X(IP_PROTOCOL_VERSION, 1, 0, 0x06)
#define FIXED_FLOW_ENTITIES_4_V6(X)                                            \
  FIXED_FLOW_ENTITIES(X)                                                       \
  X(IPV6_SRC_ADDR, 16, 0, 0x20, 0x01, 0x04, 0x28, 0xff, 0x00, 0x00, 0x00,      \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)                            \
  X(IPV6_DST_ADDR, 16, 0, 0x20, 0x01, 0x04, 0x28, 0xff, 0x00, 0x00, 0x00,      \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02)                            \
  X(IP_PROTOCOL_VERSION, 1, 0, 0x06)

#define FLOW_ENTITIES_V4(RT, R)                                                \
  /* First flow (ingress) */                                                   \
  FIXED_FLOW_ENTITIES_1_V4(RT)                                                 \
  RT(DIRECTION, 1, 0, 0x00)                                                    \
                                                                               \
  /* First flow (egress) */                                                    \
  FIXED_FLOW_ENTITIES_1_V4(R)                                                  \
  R(DIRECTION, 1, 0, 0x01)                                                     \
                                                                               \
  /* Second flow (ingress) */                                                  \
  FIXED_FLOW_ENTITIES_2_V4(R)                                                  \
  R(DIRECTION, 1, 0, 0x00)                                                     \
                                                                               \
  /* Second flow (egress) */                                                   \
  FIXED_FLOW_ENTITIES_2_V4(R)                                                  \
  R(DIRECTION, 1, 0, 0x01)                                                     \
                                                                               \
  /* Third flow (ingress) */                                                   \
  FIXED_FLOW_ENTITIES_3_V4(R)                                                  \
  R(DIRECTION, 1, 0, 0x00)                                                     \
                                                                               \
  /* Third flow (egress) */                                                    \
  FIXED_FLOW_ENTITIES_3_V4(R)                                                  \
  R(DIRECTION, 1, 0, 0x01)                                                     \
                                                                               \
  /* Fourth flow (ingress) */                                                  \
  FIXED_FLOW_ENTITIES_4_V4(R)                                                  \
  R(DIRECTION, 1, 0, 0x00)                                                     \
                                                                               \
  /* Fourth flow (egress) */                                                   \
  FIXED_FLOW_ENTITIES_4_V4(R)                                                  \
  R(DIRECTION, 1, 0, 0x01)

#define FLOW_ENTITIES_V6(RT, R)                                                \
  /* First flow (ingress) */                                                   \
  FIXED_FLOW_ENTITIES_1_V6(RT)                                                 \
  RT(DIRECTION, 1, 0, 0x00)                                                    \
                                                                               \
  /* First flow (egress) */                                                    \
  FIXED_FLOW_ENTITIES_1_V6(R)                                                  \
  R(DIRECTION, 1, 0, 0x01)                                                     \
                                                                               \
  /* Second flow (ingress) */                                                  \
  FIXED_FLOW_ENTITIES_2_V6(R)                                                  \
  R(DIRECTION, 1, 0, 0x00)                                                     \
                                                                               \
  /* Second flow (egress) */                                                   \
  FIXED_FLOW_ENTITIES_2_V6(R)                                                  \
  R(DIRECTION, 1, 0, 0x01)                                                     \
                                                                               \
  /* Third flow (ingress) */                                                   \
  FIXED_FLOW_ENTITIES_3_V6(R)                                                  \
  R(DIRECTION, 1, 0, 0x00)                                                     \
                                                                               \
  /* Third flow (egress) */                                                    \
  FIXED_FLOW_ENTITIES_3_V6(R)                                                  \
  R(DIRECTION, 1, 0, 0x01)                                                     \
                                                                               \
  /* Fourth flow (ingress) */                                                  \
  FIXED_FLOW_ENTITIES_4_V6(R)                                                  \
  R(DIRECTION, 1, 0, 0x00)                                                     \
                                                                               \
  /* Fourth flow (egress) */                                                   \
  FIXED_FLOW_ENTITIES_4_V6(R)                                                  \
  R(DIRECTION, 1, 0, 0x01)

/* Expected(not_normalized_direction, expected_normalized_direction_lan_side,
  expected_normalized_direction_wan_side,
  src_mac, dst_mac, post_dst_mac,
  src_ip, src_net, src_net_name, src_v6_ip, src_v6_net, src_v6_net_name
  dst_ip, dst_net, dst_net_name, dst_v6_ip, dst_v6_net, dst_v6_net_name,
  src_port, dst_port) */
#define EXPECTED_RESULTS_BASE(X)                                               \
  X("ingress", upstream, upstream,                                             \
    "00:24:14:01:02:03", "00:22:55:04:05:06", "00:24:1d:04:05:06",             \
    "10.13.30.44", "10.13.30.0/16", "users",                                   \
    "2001:0428:ce00:0000:0000:0000:0000:0001",                                 \
      "2001:428:ce00::/48",                                                    \
      "users6",                                                                \
    "66.220.152.19", NULL, NULL,                                               \
      "2001:0428:ff00:0000:0000:0000:0000:0002",                               \
      NULL,                                                                    \
      NULL,                                                                    \
      "54713", "443")                                                          \
  X("egress", upstream, upstream,                                              \
    "00:24:14:01:02:03", "00:22:55:04:05:06", "00:24:1d:04:05:06",             \
    "10.13.30.44", "10.13.30.0/16", "users",                                   \
    "2001:0428:ce00:0000:0000:0000:0000:0001",                                 \
      "2001:428:ce00::/48",                                                    \
      "users6",                                                                \
    "66.220.152.19", NULL, NULL,                                               \
      "2001:0428:ff00:0000:0000:0000:0000:0002",                               \
      NULL,                                                                    \
      NULL,                                                                    \
      "54713", "443")                                                          \
  X("ingress", downstream, downstream,                                         \
    "00:24:14:01:02:03", "00:22:55:04:05:06", "00:24:1d:04:05:06",             \
    "66.220.152.19", NULL, NULL,                                               \
      "2001:0428:ff00:0000:0000:0000:0000:0002",                               \
      NULL,                                                                    \
      NULL,                                                                    \
    "10.13.30.44", "10.13.30.0/16", "users",                                   \
      "2001:0428:ce00:0000:0000:0000:0000:0001",                               \
      "2001:428:ce00::/48",                                                    \
      "users6",                                                                \
    "54713", "443")                                                            \
  X("egress", downstream, downstream,                                          \
    "00:24:14:01:02:03", "00:22:55:04:05:06", "00:24:1d:04:05:06",             \
    "66.220.152.19", NULL, NULL,                                               \
      "2001:0428:ff00:0000:0000:0000:0000:0002",                               \
      NULL,                                                                    \
      NULL,                                                                    \
    "10.13.30.44", "10.13.30.0/16", "users",                                   \
    "2001:0428:ce00:0000:0000:0000:0000:0001",                                 \
      "2001:428:ce00::/48",                                                    \
      "users6",                                                                \
    "54713", "443")                                                            \
  X("ingress", internal, internal,                                             \
    "00:24:14:01:02:03", "00:22:55:04:05:06", "00:24:1d:04:05:06",             \
    "10.13.30.44", "10.13.30.0/16", "users",                                   \
    "2001:0428:ce00:0000:0000:0000:0000:0001",                                 \
        "2001:428:ce00::/48",                                                  \
        "users6",                                                              \
    "10.13.30.45", "10.13.30.0/16", "users",                                   \
    "2001:0428:ce00:0000:0000:0000:0000:0002",                                 \
      "2001:428:ce00::/48",                                                    \
      "users6",                                                                \
    "54713", "443")                                                            \
  X("egress", internal, internal,                                              \
    "00:24:14:01:02:03", "00:22:55:04:05:06", "00:24:1d:04:05:06",             \
    "10.13.30.44", "10.13.30.0/16", "users",                                   \
    "2001:0428:ce00:0000:0000:0000:0000:0001",                                 \
        "2001:428:ce00::/48",                                                  \
        "users6",                                                              \
    "10.13.30.45", "10.13.30.0/16", "users",                                   \
    "2001:0428:ce00:0000:0000:0000:0000:0002",                                 \
      "2001:428:ce00::/48",                                                    \
      "users6",                                                                \
    "54713", "443")                                                            \
  X("ingress", upstream, downstream,                                           \
    "00:24:14:01:02:03", "00:22:55:04:05:06", "00:24:1d:04:05:06",             \
    "66.220.152.19", NULL, NULL,                                               \
      "2001:0428:ff00:0000:0000:0000:0000:0001",                               \
      NULL,                                                                    \
      NULL,                                                                    \
    "66.220.152.20", NULL, NULL,                                               \
    "2001:0428:ff00:0000:0000:0000:0000:0002",                                 \
        NULL,                                                                  \
        NULL,                                                                  \
        "54713", "443")                                                        \
  X("egress", downstream, upstream,                                            \
    "00:24:14:01:02:03", "00:22:55:04:05:06", "00:24:1d:04:05:06",             \
    "66.220.152.19", NULL, NULL,                                               \
      "2001:0428:ff00:0000:0000:0000:0000:0001",                               \
      NULL,                                                                    \
      NULL,                                                                    \
    "66.220.152.20", NULL, NULL,                                               \
    "2001:0428:ff00:0000:0000:0000:0000:0002",                                 \
        NULL,                                                                  \
        NULL,                                                                  \
    "54713", "443")

#define NOT_NORMALIZED_CHECKDATA(t_direction,                                  \
    t_src_mac, t_dst_mac, t_post_dst_mac,                                      \
    t_src_ip, t_src_net, t_src_net_name,                                       \
    t_dst_ip, t_dst_net, t_dst_net_name,                                       \
    t_src_port, dst_port)                                                      \
  {.size=12, .checks = (struct checkdata_value[]) {                            \
        {.key = "direction", .value=t_direction},                              \
        {.key = "src_mac", .value=t_src_mac},                                  \
        {.key = "dst_mac", .value=t_dst_mac},                                  \
        {.key = "post_dst_mac", .value=t_post_dst_mac},                        \
        {.key = "src", .value=t_src_ip},                                       \
        {.key = "src_net", .value = t_src_net},                                \
        {.key = "src_net_name", .value = t_src_net_name},                      \
        {.key = "dst", .value=t_dst_ip},                                       \
        {.key = "dst_net", .value = t_dst_net},                                \
        {.key = "dst_net_name", .value = t_dst_net_name},                      \
        {.key = "src_port", .value=t_src_port},                                \
        {.key = "dst_port", .value=dst_port}}},

#define V4_NO_NORMALIZE_CHECKDATA(t_direction,                                 \
		lan_side_normalized_direction, wan_side_normalized_direction,  \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)                                          \
	NOT_NORMALIZED_CHECKDATA(t_direction,                                  \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)

#define V6_NO_NORMALIZE_CHECKDATA(t_direction,                                 \
	        lan_side_normalized_direction, wan_side_normalized_direction,  \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)                                          \
	NOT_NORMALIZED_CHECKDATA(t_direction,                                  \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)

#define NORMALIZED_CHECKDATA(direction, client_mac,\
  lan_ip, lan_ip_net, lan_ip_net_name, \
  wan_ip, wan_ip_net, wan_ip_net_name, \
  lan_port, wan_port) \
    {.size=10, .checks = (struct checkdata_value[]) { \
        {.key = "direction", .value=direction}, \
        {.key = "client_mac", .value=client_mac}, \
        {.key = "lan_ip", .value=lan_ip}, \
        {.key = "lan_ip_net", .value = lan_ip_net}, \
        {.key = "lan_ip_net_name", .value = lan_ip_net_name}, \
        {.key = "wan_ip", .value=wan_ip}, \
        {.key = "wan_ip_net", .value = wan_ip_net}, \
        {.key = "wan_ip_net_name", .value = wan_ip_net_name}, \
        {.key = "lan_l4_port", .value=lan_port}, \
        {.key = "wan_l4_port", .value=wan_port}}},


#define CHECKDATA_NORMALIZE_upstream(t_src_mac, t_dst_mac,                     \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)                                          \
	NORMALIZED_CHECKDATA("upstream", t_src_mac,                            \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)

#define CHECKDATA_NORMALIZE_downstream(t_src_mac, t_dst_mac,                   \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)                                          \
	NORMALIZED_CHECKDATA("downstream", t_dst_mac,                          \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_ip, t_src_net, t_src_net_name,                           \
		dst_port, t_src_port)

#define CHECKDATA_NORMALIZE_internal(t_src_mac, t_dst_mac,                     \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)                                          \
	NORMALIZED_CHECKDATA("internal", t_src_mac,                            \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)


/// Select dst mac based on span mode
#define CHECKDATA_NO_SPAN_NORMALIZE_CHECKDATA(direction,                       \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)                                          \
	CHECKDATA_NORMALIZE_##direction (                                      \
		t_src_mac, t_post_dst_mac,                                     \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)

#define CHECKDATA_SPAN_NORMALIZE_CHECKDATA(direction,                          \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)                                          \
	CHECKDATA_NORMALIZE_##direction (                                      \
		t_src_mac, t_dst_mac,                                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)

/// Select checkdata V4 IP
#define V4_LAN_NO_SPAN_NORMALIZE_CHECKDATA(t_direction,                        \
		lan_normalized_direction, wan_normalized_direction,            \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)                                          \
	CHECKDATA_NO_SPAN_NORMALIZE_CHECKDATA(lan_normalized_direction,        \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)

/// Select checkdata V6 IP
#define V6_LAN_NO_SPAN_NORMALIZE_CHECKDATA(t_direction,                        \
		lan_normalized_direction, wan_normalized_direction,            \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)                                          \
	CHECKDATA_NO_SPAN_NORMALIZE_CHECKDATA(lan_normalized_direction,        \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)

/// Select checkdata V4 IP
#define V4_LAN_SPAN_NORMALIZE_CHECKDATA(t_direction,                           \
		lan_normalized_direction, wan_normalized_direction,            \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)                                          \
	CHECKDATA_SPAN_NORMALIZE_CHECKDATA(lan_normalized_direction,           \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)

/// Select checkdata V6 IP
#define V6_LAN_SPAN_NORMALIZE_CHECKDATA(t_direction,                           \
		lan_normalized_direction, wan_normalized_direction,            \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)                                          \
	CHECKDATA_SPAN_NORMALIZE_CHECKDATA(lan_normalized_direction,           \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)

/// Select checkdata V4 IP when exporter is in WAN side
#define V4_WAN_NO_SPAN_NORMALIZE_CHECKDATA(t_direction,                        \
		lan_normalized_direction, wan_normalized_direction,            \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)                                          \
	CHECKDATA_NO_SPAN_NORMALIZE_CHECKDATA(wan_normalized_direction,        \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)

/// Select checkdata V6 IP when exporter is in WAN side
#define V6_WAN_NO_SPAN_NORMALIZE_CHECKDATA(t_direction,                        \
		lan_normalized_direction, wan_normalized_direction,            \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)                                          \
	CHECKDATA_NO_SPAN_NORMALIZE_CHECKDATA(wan_normalized_direction,        \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)

/// Select checkdata V4 IP when exporter is in WAN side
#define V4_WAN_SPAN_NORMALIZE_CHECKDATA(t_direction,                           \
		lan_normalized_direction, wan_normalized_direction,            \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)                                          \
	CHECKDATA_SPAN_NORMALIZE_CHECKDATA(wan_normalized_direction,           \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_src_port, dst_port)

/// Select checkdata V6 IP when exporter is in WAN side
#define V6_WAN_SPAN_NORMALIZE_CHECKDATA(t_direction,                           \
		lan_normalized_direction, wan_normalized_direction,            \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_ip, t_src_net, t_src_net_name,                           \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_ip, t_dst_net, t_dst_net_name,                           \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)                                          \
	CHECKDATA_SPAN_NORMALIZE_CHECKDATA(wan_normalized_direction,           \
		t_src_mac, t_dst_mac, t_post_dst_mac,                          \
		t_src_v6_ip, t_src_v6_net, t_src_v6_net_name,                  \
		t_dst_v6_ip, t_dst_v6_net, t_dst_v6_net_name,                  \
		t_src_port, dst_port)

static const IPFIX_TEMPLATE(v10Template, TEST_FLOW_HEADER, TEST_TEMPLATE_ID_V4,
                            FLOW_ENTITIES_V4);
static const IPFIX_FLOW(v10Flow, TEST_FLOW_HEADER, TEST_TEMPLATE_ID_V4,
                        FLOW_ENTITIES_V4);

static const IPFIX_TEMPLATE(v10Template_v6, TEST_FLOW_HEADER,
                            TEST_TEMPLATE_ID_V6, FLOW_ENTITIES_V6);
static const IPFIX_FLOW(v10Flow_v6, TEST_FLOW_HEADER, TEST_TEMPLATE_ID_V6,
                        FLOW_ENTITIES_V6);


struct exporter_side_tests {
	struct {
		const struct checkdata *checks;
		size_t size;
	} checkdata_span_true_v4, checkdata_span_false_v4,
	  checkdata_span_true_v6, checkdata_span_false_v6;
};

struct test_mac_direction_params {
	struct exporter_side_tests lan,wan;
};

static int prepare_test_nf10_mac_direction_base(void **state,
		const struct test_mac_direction_params *params,
		bool normalize_directions) {

#define TEST(nf_dev_ip, mrecord, mrecord_size, checks, checks_size,...) {      \
	.netflow_src_ip = nf_dev_ip,                                           \
	.record = mrecord, .record_size = mrecord_size,                        \
	.checkdata = checks, .checkdata_size = checks_size,                    \
	__VA_ARGS__ }

#define TEST_TEMPLATE_FLOW(nf_dev_ip, template, template_size,                 \
			flow, flow_size, checks, checks_size, ...)             \
	TEST(nf_dev_ip, template, template_size, NULL, 0, __VA_ARGS__),        \
	TEST(nf_dev_ip, flow, flow_size, checks, checks_size,)

	const struct test_params test_params[] = {
		// LAN SIDE: span true, span false, no span specified (false)
		TEST_TEMPLATE_FLOW(0x04030201,
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			params->lan.checkdata_span_true_v4.checks,
			params->lan.checkdata_span_true_v4.size,
			.config_json_path = "./tests/0015-testMacDirection.json",
			.normalize_directions = normalize_directions),
		TEST_TEMPLATE_FLOW(0x04030301,
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			params->lan.checkdata_span_false_v4.checks,
			params->lan.checkdata_span_false_v4.size,),
		TEST_TEMPLATE_FLOW(0x04030401,
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			params->lan.checkdata_span_false_v4.checks,
			params->lan.checkdata_span_false_v4.size,),
		TEST_TEMPLATE_FLOW(0x04030201,
			&v10Template_v6, sizeof(v10Template_v6),
			&v10Flow_v6, sizeof(v10Flow_v6),
			params->lan.checkdata_span_true_v6.checks,
			params->lan.checkdata_span_true_v6.size,),
		TEST_TEMPLATE_FLOW(0x04030301,
			&v10Template_v6, sizeof(v10Template_v6),
			&v10Flow_v6, sizeof(v10Flow_v6),
			params->lan.checkdata_span_false_v6.checks,
			params->lan.checkdata_span_false_v6.size,),
		TEST_TEMPLATE_FLOW(0x04030401,
			&v10Template_v6, sizeof(v10Template_v6),
			&v10Flow_v6, sizeof(v10Flow_v6),
			params->lan.checkdata_span_false_v6.checks,
			params->lan.checkdata_span_false_v6.size,),

		// WAN SIDE: span true, span false, no span specified (false)
		// @todo delete ifs
		TEST_TEMPLATE_FLOW(0x04040201,
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			params->wan.checkdata_span_true_v4.checks,
			params->wan.checkdata_span_true_v4.size,),
		TEST_TEMPLATE_FLOW(0x04040301,
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			params->wan.checkdata_span_false_v4.checks,
			params->wan.checkdata_span_false_v4.size,),
		TEST_TEMPLATE_FLOW(0x04040401,
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			params->wan.checkdata_span_false_v4.checks,
			params->wan.checkdata_span_false_v4.size,),
		TEST_TEMPLATE_FLOW(0x04040201,
			&v10Template_v6, sizeof(v10Template_v6),
			&v10Flow_v6, sizeof(v10Flow_v6),
			params->wan.checkdata_span_true_v6.checks,
			params->wan.checkdata_span_true_v6.size,),
		TEST_TEMPLATE_FLOW(0x04040301,
			&v10Template_v6, sizeof(v10Template_v6),
			&v10Flow_v6, sizeof(v10Flow_v6),
			params->wan.checkdata_span_false_v6.checks,
			params->wan.checkdata_span_false_v6.size,),
		TEST_TEMPLATE_FLOW(0x04040401,
			&v10Template_v6, sizeof(v10Template_v6),
			&v10Flow_v6, sizeof(v10Flow_v6),
			params->wan.checkdata_span_false_v6.checks,
			params->wan.checkdata_span_false_v6.size,),
        };

        *state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
        return *state == NULL;
}

static const struct checkdata checkdata_dont_normalize_ipv4[] = {
	EXPECTED_RESULTS_BASE(V4_NO_NORMALIZE_CHECKDATA)
};

static const struct checkdata checkdata_dont_normalize_ipv6[] = {
	EXPECTED_RESULTS_BASE(V6_NO_NORMALIZE_CHECKDATA)
};

static int prepare_test_nf10_dont_normalize(void **state) {
	static const struct test_mac_direction_params params = {
		.lan.checkdata_span_true_v4.checks =
			checkdata_dont_normalize_ipv4,
		.lan.checkdata_span_true_v4.size =
			RD_ARRAYSIZE(checkdata_dont_normalize_ipv4),
		.lan.checkdata_span_false_v4.checks =
			checkdata_dont_normalize_ipv4,
		.lan.checkdata_span_false_v4.size =
			RD_ARRAYSIZE(checkdata_dont_normalize_ipv4),
		.lan.checkdata_span_true_v6.checks =
			checkdata_dont_normalize_ipv6,
		.lan.checkdata_span_true_v6.size =
			RD_ARRAYSIZE(checkdata_dont_normalize_ipv6),
		.lan.checkdata_span_false_v6.checks =
			checkdata_dont_normalize_ipv6,
		.lan.checkdata_span_false_v6.size =
			RD_ARRAYSIZE(checkdata_dont_normalize_ipv6),

		.wan.checkdata_span_true_v4.checks =
			checkdata_dont_normalize_ipv4,
		.wan.checkdata_span_true_v4.size =
			RD_ARRAYSIZE(checkdata_dont_normalize_ipv4),
		.wan.checkdata_span_false_v4.checks =
			checkdata_dont_normalize_ipv4,
		.wan.checkdata_span_false_v4.size =
			RD_ARRAYSIZE(checkdata_dont_normalize_ipv4),
		.wan.checkdata_span_true_v6.checks =
			checkdata_dont_normalize_ipv6,
		.wan.checkdata_span_true_v6.size =
			RD_ARRAYSIZE(checkdata_dont_normalize_ipv6),
		.wan.checkdata_span_false_v6.checks =
			checkdata_dont_normalize_ipv6,
		.wan.checkdata_span_false_v6.size =
			RD_ARRAYSIZE(checkdata_dont_normalize_ipv6),
	};

	return prepare_test_nf10_mac_direction_base(state, &params, false);
}

static const struct checkdata checkdata_span_true_v4[] = {
	EXPECTED_RESULTS_BASE(V4_LAN_SPAN_NORMALIZE_CHECKDATA)
};

static const struct checkdata checkdata_span_false_v4[] = {
	EXPECTED_RESULTS_BASE(V4_LAN_NO_SPAN_NORMALIZE_CHECKDATA)
};

static const struct checkdata checkdata_span_true_v6[] = {
	EXPECTED_RESULTS_BASE(V6_LAN_SPAN_NORMALIZE_CHECKDATA)
};

static const struct checkdata checkdata_span_false_v6[] = {
	EXPECTED_RESULTS_BASE(V6_LAN_NO_SPAN_NORMALIZE_CHECKDATA)
};

// In WAN mode, we just need to reverse expected directions
#define WAN_DIRECTION_OF_LAN_upstream downstream
#define WAN_DIRECTION_OF_LAN_downstream upstream
#define WAN_DIRECTION_OF_LAN_internal internal

static const struct checkdata wan_checkdata_span_true_v4[] = {
	EXPECTED_RESULTS_BASE(V4_WAN_SPAN_NORMALIZE_CHECKDATA)
};

static const struct checkdata wan_checkdata_span_false_v4[] = {
	EXPECTED_RESULTS_BASE(V4_WAN_NO_SPAN_NORMALIZE_CHECKDATA)
};

static const struct checkdata wan_checkdata_span_true_v6[] = {
	EXPECTED_RESULTS_BASE(V6_WAN_SPAN_NORMALIZE_CHECKDATA)
};

static const struct checkdata wan_checkdata_span_false_v6[] = {
	EXPECTED_RESULTS_BASE(V6_WAN_NO_SPAN_NORMALIZE_CHECKDATA)
};

static int prepare_test_nf10_mac_direction(void **state) {
	static const struct test_mac_direction_params params = {
		.lan.checkdata_span_true_v4.checks = checkdata_span_true_v4,
		.lan.checkdata_span_true_v4.size =
			RD_ARRAYSIZE(checkdata_span_true_v4),
		.lan.checkdata_span_false_v4.checks = checkdata_span_false_v4,
		.lan.checkdata_span_false_v4.size =
			RD_ARRAYSIZE(checkdata_span_false_v4),
		.lan.checkdata_span_true_v6.checks = checkdata_span_true_v6,
		.lan.checkdata_span_true_v6.size =
			RD_ARRAYSIZE(checkdata_span_true_v6),
		.lan.checkdata_span_false_v6.checks = checkdata_span_false_v6,
		.lan.checkdata_span_false_v6.size =
			RD_ARRAYSIZE(checkdata_span_false_v6),

		.wan.checkdata_span_true_v4.checks = wan_checkdata_span_true_v4,
		.wan.checkdata_span_true_v4.size =
			RD_ARRAYSIZE(wan_checkdata_span_true_v4),
		.wan.checkdata_span_false_v4.checks =
			wan_checkdata_span_false_v4,
		.wan.checkdata_span_false_v4.size =
			RD_ARRAYSIZE(wan_checkdata_span_false_v4),
		.wan.checkdata_span_true_v6.checks = wan_checkdata_span_true_v6,
		.wan.checkdata_span_true_v6.size =
			RD_ARRAYSIZE(wan_checkdata_span_true_v6),
		.wan.checkdata_span_false_v6.checks = wan_checkdata_span_false_v6,
		.wan.checkdata_span_false_v6.size =
			RD_ARRAYSIZE(wan_checkdata_span_false_v6),

	};
	static const bool normalize = true;
	return prepare_test_nf10_mac_direction_base(state, &params, normalize);
}

/// @todo should this be 3 different tests?
int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
			prepare_test_nf10_dont_normalize),
		cmocka_unit_test_setup(testFlow,
					prepare_test_nf10_mac_direction),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
