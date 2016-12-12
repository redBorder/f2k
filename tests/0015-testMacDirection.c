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
  X(DIRECTION, 1, 0, 0x00)                                                     \
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

#define CHECKDATA(direction, client_mac, \
  client_ip, client_ip_net, client_ip_net_name, \
  target_ip, target_ip_net, target_ip_net_name, \
  client_port, target_port) \
    {.size=10, .checks = (struct checkdata_value[]) { \
        {.key = "direction", .value=direction}, \
        {.key = "client_mac", .value=client_mac}, \
        {.key = "client_ip", .value=client_ip}, \
        {.key = "client_ip_net", .value = client_ip_net}, \
        {.key = "client_ip_net_name", .value = client_ip_net_name}, \
        {.key = "target_ip", .value=target_ip}, \
        {.key = "target_ip_net", .value = target_ip_net}, \
        {.key = "target_ip_net_name", .value = target_ip_net_name}, \
        {.key = "client_port", .value=client_port}, \
        {.key = "target_port", .value=target_port}}}

static const struct checkdata checkdata_span_true_v4[] = {
	CHECKDATA("ingress", "00:24:14:01:02:03",
    "10.13.30.44", "10.13.30.0/16", "users",
    "66.220.152.19", NULL, NULL,
    "54713", "443"),
	CHECKDATA("ingress", "00:24:14:01:02:03",
    "10.13.30.44", "10.13.30.0/16", "users",
    "66.220.152.19", NULL, NULL,
    "54713", "443"),
	CHECKDATA("egress", "00:22:55:04:05:06",
    "10.13.30.44", "10.13.30.0/16", "users",
    "66.220.152.19", NULL, NULL,
    "443", "54713"),
	CHECKDATA("egress", "00:22:55:04:05:06",
    "10.13.30.44", "10.13.30.0/16", "users",
    "66.220.152.19", NULL, NULL,
    "443", "54713"),
	CHECKDATA("internal", "00:22:55:04:05:06",
    "10.13.30.45", "10.13.30.0/16", "users",
    "10.13.30.44", "10.13.30.0/16", "users",
    "443", "54713"),
	CHECKDATA("internal", "00:22:55:04:05:06",
    "10.13.30.45", "10.13.30.0/16", "users",
    "10.13.30.44", "10.13.30.0/16", "users",
    "443", "54713"),
	CHECKDATA("ingress", "00:24:14:01:02:03",
    "66.220.152.19", NULL, NULL,
    "66.220.152.20", NULL, NULL,
    "54713", "443"),
	CHECKDATA("egress", "00:22:55:04:05:06",
    "66.220.152.20", NULL, NULL,
    "66.220.152.19", NULL, NULL,
    "443", "54713"),
};

static const struct checkdata checkdata_span_false_v4[] = {
	CHECKDATA("ingress", "00:24:14:01:02:03",
    "10.13.30.44", "10.13.30.0/16", "users",
    "66.220.152.19", NULL, NULL,
    "54713", "443"),
	CHECKDATA("ingress", "00:24:14:01:02:03",
    "10.13.30.44", "10.13.30.0/16", "users",
    "66.220.152.19", NULL, NULL,
    "54713", "443"),
	CHECKDATA("egress", "00:24:1d:04:05:06",
    "10.13.30.44", "10.13.30.0/16", "users",
    "66.220.152.19", NULL, NULL,
    "443", "54713"),
	CHECKDATA("egress", "00:24:1d:04:05:06",
    "10.13.30.44", "10.13.30.0/16", "users",
    "66.220.152.19", NULL, NULL,
    "443", "54713"),
	CHECKDATA("internal", "00:24:1d:04:05:06",
    "10.13.30.45", "10.13.30.0/16", "users",
    "10.13.30.44", "10.13.30.0/16", "users",
    "443", "54713"),
	CHECKDATA("internal", "00:24:1d:04:05:06",
    "10.13.30.45", "10.13.30.0/16", "users",
    "10.13.30.44", "10.13.30.0/16", "users",
    "443", "54713"),
	CHECKDATA("ingress", "00:24:14:01:02:03",
    "66.220.152.19", NULL, NULL,
    "66.220.152.20", NULL, NULL,
    "54713", "443"),
	CHECKDATA("egress", "00:24:1d:04:05:06",
    "66.220.152.20", NULL, NULL,
    "66.220.152.19", NULL, NULL,
    "443", "54713"),
};

static const struct checkdata checkdata_span_true_v6[] = {
    CHECKDATA("ingress", "00:24:14:01:02:03",
      "2001:0428:ce00:0000:0000:0000:0000:0001",
        "2001:0428:ce00:0000:0000:0000:0000:0000/48",
        "users6",
      "2001:0428:ff00:0000:0000:0000:0000:0002",
        NULL,
        NULL,
      "54713", "443"),
    CHECKDATA("ingress", "00:24:14:01:02:03",
      "2001:0428:ce00:0000:0000:0000:0000:0001",
        "2001:0428:ce00:0000:0000:0000:0000:0000/48",
        "users6",
      "2001:0428:ff00:0000:0000:0000:0000:0002",
        NULL,
        NULL,
      "54713", "443"),
    CHECKDATA("egress", "00:22:55:04:05:06",
      "2001:0428:ce00:0000:0000:0000:0000:0001",
        "2001:0428:ce00:0000:0000:0000:0000:0000/48",
        "users6",
      "2001:0428:ff00:0000:0000:0000:0000:0002",
        NULL,
        NULL,
      "443", "54713"),
    CHECKDATA("egress", "00:22:55:04:05:06",
      "2001:0428:ce00:0000:0000:0000:0000:0001",
        "2001:0428:ce00:0000:0000:0000:0000:0000/48",
        "users6",
      "2001:0428:ff00:0000:0000:0000:0000:0002",
        NULL,
        NULL,
      "443", "54713"),
    CHECKDATA("internal", "00:22:55:04:05:06",
      "2001:0428:ce00:0000:0000:0000:0000:0002",
        "2001:0428:ce00:0000:0000:0000:0000:0000/48",
        "users6",
      "2001:0428:ce00:0000:0000:0000:0000:0001",
        "2001:0428:ce00:0000:0000:0000:0000:0000/48",
        "users6",
      "443", "54713"),
    CHECKDATA("internal", "00:22:55:04:05:06",
      "2001:0428:ce00:0000:0000:0000:0000:0002",
        "2001:0428:ce00:0000:0000:0000:0000:0000/48",
        "users6",
      "2001:0428:ce00:0000:0000:0000:0000:0001",
        "2001:0428:ce00:0000:0000:0000:0000:0000/48",
        "users6",
      "443", "54713"),
    CHECKDATA("ingress", "00:24:14:01:02:03",
      "2001:0428:ff00:0000:0000:0000:0000:0001",
        NULL,
        NULL,
      "2001:0428:ff00:0000:0000:0000:0000:0002",
        NULL,
        NULL,
      "54713", "443"),
    CHECKDATA("egress", "00:22:55:04:05:06",
      "2001:0428:ff00:0000:0000:0000:0000:0002",
        NULL,
        NULL,
      "2001:0428:ff00:0000:0000:0000:0000:0001",
        NULL,
        NULL,
      "443", "54713"),
};

static const struct checkdata checkdata_span_false_v6[] = {
	CHECKDATA("ingress", "00:24:14:01:02:03",
    "2001:0428:ce00:0000:0000:0000:0000:0001",
      "2001:0428:ce00:0000:0000:0000:0000:0000/48",
      "users6",
    "2001:0428:ff00:0000:0000:0000:0000:0002",
      NULL,
      NULL,
    "54713", "443"),
	CHECKDATA("ingress", "00:24:14:01:02:03",
    "2001:0428:ce00:0000:0000:0000:0000:0001",
      "2001:0428:ce00:0000:0000:0000:0000:0000/48",
      "users6",
    "2001:0428:ff00:0000:0000:0000:0000:0002",
      NULL,
      NULL,
    "54713", "443"),
	CHECKDATA("egress", "00:24:1d:04:05:06",
    "2001:0428:ce00:0000:0000:0000:0000:0001",
      "2001:0428:ce00:0000:0000:0000:0000:0000/48",
      "users6",
    "2001:0428:ff00:0000:0000:0000:0000:0002",
      NULL,
      NULL,
    "443", "54713"),
	CHECKDATA("egress", "00:24:1d:04:05:06",
    "2001:0428:ce00:0000:0000:0000:0000:0001",
      "2001:0428:ce00:0000:0000:0000:0000:0000/48",
      "users6",
    "2001:0428:ff00:0000:0000:0000:0000:0002",
      NULL,
      NULL,
    "443", "54713"),
	CHECKDATA("internal", "00:24:1d:04:05:06",
    "2001:0428:ce00:0000:0000:0000:0000:0002",
      "2001:0428:ce00:0000:0000:0000:0000:0000/48",
      "users6",
    "2001:0428:ce00:0000:0000:0000:0000:0001",
      "2001:0428:ce00:0000:0000:0000:0000:0000/48",
      "users6",
    "443", "54713"),
	CHECKDATA("internal", "00:24:1d:04:05:06",
    "2001:0428:ce00:0000:0000:0000:0000:0002",
      "2001:0428:ce00:0000:0000:0000:0000:0000/48",
      "users6",
    "2001:0428:ce00:0000:0000:0000:0000:0001",
      "2001:0428:ce00:0000:0000:0000:0000:0000/48",
      "users6",
    "443", "54713"),
	CHECKDATA("ingress", "00:24:14:01:02:03",
    "2001:0428:ff00:0000:0000:0000:0000:0001",
      NULL,
      NULL,
    "2001:0428:ff00:0000:0000:0000:0000:0002",
      NULL,
      NULL,
    "54713", "443"),
	CHECKDATA("egress", "00:24:1d:04:05:06",
    "2001:0428:ff00:0000:0000:0000:0000:0002",
      NULL,
      NULL,
    "2001:0428:ff00:0000:0000:0000:0000:0001",
      NULL,
      NULL,
    "443", "54713"),
};

static int prepare_test_nf10_mac_direction(void **state) {
	static const IPFIX_TEMPLATE(v10Template, TEST_FLOW_HEADER, TEST_TEMPLATE_ID_V4,
	                            FLOW_ENTITIES_V4);
	static const IPFIX_FLOW(v10Flow, TEST_FLOW_HEADER, TEST_TEMPLATE_ID_V4,
	                        FLOW_ENTITIES_V4);

	static const IPFIX_TEMPLATE(v10Template_v6, TEST_FLOW_HEADER,
	                            TEST_TEMPLATE_ID_V6, FLOW_ENTITIES_V6);
	static const IPFIX_FLOW(v10Flow_v6, TEST_FLOW_HEADER, TEST_TEMPLATE_ID_V6,
	                        FLOW_ENTITIES_V6);

#define TEST(config_path, nf_dev_ip, mrecord, mrecord_size, checks,            \
								checks_size) { \
		.config_json_path = config_path, .netflow_src_ip = nf_dev_ip,  \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size             \
	}

#define TEST_TEMPLATE_FLOW(config_path, nf_dev_ip, template, template_size,    \
			flow, flow_size, checks, checks_size)                  \
	TEST(config_path, nf_dev_ip, template, template_size, NULL, 0),        \
	TEST(NULL, nf_dev_ip, flow, flow_size, checks, checks_size)


	struct test_params test_params[] = {
		TEST_TEMPLATE_FLOW("./tests/0015-testMacDirection.json",
			0x04030201,
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			checkdata_span_true_v4, RD_ARRAYSIZE(checkdata_span_true_v4)),
		TEST_TEMPLATE_FLOW(NULL, 0x04030301,
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			checkdata_span_false_v4,
			RD_ARRAYSIZE(checkdata_span_false_v4)),
		TEST_TEMPLATE_FLOW(NULL, 0x04030401,
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			checkdata_span_false_v4,
			RD_ARRAYSIZE(checkdata_span_false_v4)),

		TEST_TEMPLATE_FLOW(NULL, 0x04030201,
			&v10Template_v6, sizeof(v10Template_v6),
			&v10Flow_v6, sizeof(v10Flow_v6),
			checkdata_span_true_v6, RD_ARRAYSIZE(checkdata_span_true_v6)),
		TEST_TEMPLATE_FLOW(NULL, 0x04030301,
			&v10Template_v6, sizeof(v10Template_v6),
			&v10Flow_v6, sizeof(v10Flow_v6),
			checkdata_span_false_v6,
			RD_ARRAYSIZE(checkdata_span_false_v6)),
		TEST_TEMPLATE_FLOW(NULL, 0x04030401,
			&v10Template_v6, sizeof(v10Template_v6),
			&v10Flow_v6, sizeof(v10Flow_v6),
			checkdata_span_false_v6,
			RD_ARRAYSIZE(checkdata_span_false_v6)),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

/// @todo should this be 3 different tests?
int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
					prepare_test_nf10_mac_direction),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
