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

#define TEST_TEMPLATE_ID 512

#define TEST_FLOW_HEADER \
	.unix_secs = constexpr_be32toh(3713886546), \
	.flow_sequence = constexpr_be32toh(232117909), \
	.observationDomainId = 65536

#define FIXED_FLOW_ENTITIES(X)                                                \
	X(PROTOCOL, 1, 0, 0x06)                                                     \
	X(FLOW_END_REASON, 1, 0, 0x03)                                              \
	X(BIFLOW_DIRECTION, 1, 0, 0x01)                                             \
	X(TRANSACTION_ID, 8, 0, 0x8f, 0x63, 0xf3, 0x40, 0x00, 0x01, 0x00, 0x00)     \
	X(DIRECTION, 1, 0, 0x00)                                                    \
	X(FLOW_SAMPLER_ID, 1, 0, 0x00)                                              \
	X(APPLICATION_ID, 4, 0, 0x03, 0x00, 0x00, 0x50)                             \
	X(IN_BYTES, 8, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xb8)           \
	X(IN_PKTS, 4, 0, 0x00, 0x00, 0x00, 0x1f)                                    \
	X(FIRST_SWITCHED, 4, 0, 0x0f, 0xed, 0x0a, 0xc0)                             \
	X(LAST_SWITCHED, 4, 0, 0x0f, 0xee, 0x18, 0x00)                              \

#define FLOW_ENTITIES(RT, R)                                                   \
  /* First flow (ingress) */                                                   \
  FIXED_FLOW_ENTITIES(RT)                                                      \
  RT(IPV4_SRC_ADDR, 4, 0, 10, 13, 30, 44)                                      \
  RT(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19)                                    \
  RT(IP_PROTOCOL_VERSION, 1, 0, 0x04)                                          \
  RT(L4_SRC_PORT, 2, 0, 0xd5, 0xb9)                                            \
  RT(L4_DST_PORT, 2, 0, 0x01, 0xbb)                                            \
  RT(IN_SRC_MAC, 6, 0, 0x00, 0x24, 0x14, 0x01, 0x02, 0x03)                     \
  RT(IN_DST_MAC, 6, 0, 0x00, 0x22, 0x55, 0x04, 0x05, 0x06)                     \
  RT(OUT_DST_MAC, 6, 0, 0x00, 0x24, 0x1d, 0x04, 0x05, 0x06)                    \
  RT(DIRECTION, 1, 0, 0x00)                                                    \
  /* First flow (egress) */                                                    \
  FIXED_FLOW_ENTITIES(R)                                                       \
  R(IPV4_SRC_ADDR, 4, 0, 10, 13, 30, 44)                                       \
  R(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19)                                     \
  R(IP_PROTOCOL_VERSION, 1, 0, 0x04)                                           \
  R(L4_SRC_PORT, 2, 0, 0xd5, 0xb9)                                             \
  R(L4_DST_PORT, 2, 0, 0x01, 0xbb)                                             \
  R(IN_SRC_MAC, 6, 0, 0x00, 0x24, 0x14, 0x01, 0x02, 0x03)                      \
  R(IN_DST_MAC, 6, 0, 0x00, 0x22, 0x55, 0x04, 0x05, 0x06)                      \
  R(OUT_DST_MAC, 6, 0, 0x00, 0x24, 0x1d, 0x04, 0x05, 0x06)                     \
  R(DIRECTION, 1, 0, 0x01)                                                     \
  /* Second flow (ingress) */                                                  \
  FIXED_FLOW_ENTITIES(R)                                                       \
  R(IPV4_SRC_ADDR, 4, 0, 66, 220, 152, 19)                                     \
  R(IPV4_DST_ADDR, 4, 0, 10, 13, 30, 44)                                       \
  R(IP_PROTOCOL_VERSION, 1, 0, 0x04)                                           \
  R(L4_SRC_PORT, 2, 0, 0xd5, 0xb9)                                             \
  R(L4_DST_PORT, 2, 0, 0x01, 0xbb)                                             \
  R(IN_SRC_MAC, 6, 0, 0x00, 0x24, 0x14, 0x01, 0x02, 0x03)                      \
  R(IN_DST_MAC, 6, 0, 0x00, 0x22, 0x55, 0x04, 0x05, 0x06)                      \
  R(OUT_DST_MAC, 6, 0, 0x00, 0x24, 0x1d, 0x04, 0x05, 0x06)                     \
  R(DIRECTION, 1, 0, 0x00)                                                     \
  /* Second flow (egress) */                                                   \
  FIXED_FLOW_ENTITIES(R)                                                       \
  R(IPV4_SRC_ADDR, 4, 0, 66, 220, 152, 19)                                     \
  R(IPV4_DST_ADDR, 4, 0, 10, 13, 30, 44)                                       \
  R(IP_PROTOCOL_VERSION, 1, 0, 0x04)                                           \
  R(L4_SRC_PORT, 2, 0, 0xd5, 0xb9)                                             \
  R(L4_DST_PORT, 2, 0, 0x01, 0xbb)                                             \
  R(IN_SRC_MAC, 6, 0, 0x00, 0x24, 0x14, 0x01, 0x02, 0x03)                      \
  R(IN_DST_MAC, 6, 0, 0x00, 0x22, 0x55, 0x04, 0x05, 0x06)                      \
  R(OUT_DST_MAC, 6, 0, 0x00, 0x24, 0x1d, 0x04, 0x05, 0x06)                     \
  R(DIRECTION, 1, 0, 0x01)                                                     \
  /* Third flow (ingress) */                                                   \
  FIXED_FLOW_ENTITIES(R)                                                       \
  R(IPV4_SRC_ADDR, 4, 0, 10, 13, 30, 44)                                       \
  R(IPV4_DST_ADDR, 4, 0, 10, 13, 30, 45)                                       \
  R(IP_PROTOCOL_VERSION, 1, 0, 0x04)                                           \
  R(L4_SRC_PORT, 2, 0, 0xd5, 0xb9)                                             \
  R(L4_DST_PORT, 2, 0, 0x01, 0xbb)                                             \
  R(IN_SRC_MAC, 6, 0, 0x00, 0x24, 0x14, 0x01, 0x02, 0x03)                      \
  R(IN_DST_MAC, 6, 0, 0x00, 0x22, 0x55, 0x04, 0x05, 0x06)                      \
  R(OUT_DST_MAC, 6, 0, 0x00, 0x24, 0x1d, 0x04, 0x05, 0x06)                     \
  R(DIRECTION, 1, 0, 0x00)                                                     \
  /* Third flow (egress) */                                                    \
  FIXED_FLOW_ENTITIES(R)                                                       \
  R(IPV4_SRC_ADDR, 4, 0, 10, 13, 30, 44)                                       \
  R(IPV4_DST_ADDR, 4, 0, 10, 13, 30, 45)                                       \
  R(IP_PROTOCOL_VERSION, 1, 0, 0x04)                                           \
  R(L4_SRC_PORT, 2, 0, 0xd5, 0xb9)                                             \
  R(L4_DST_PORT, 2, 0, 0x01, 0xbb)                                             \
  R(IN_SRC_MAC, 6, 0, 0x00, 0x24, 0x14, 0x01, 0x02, 0x03)                      \
  R(IN_DST_MAC, 6, 0, 0x00, 0x22, 0x55, 0x04, 0x05, 0x06)                      \
  R(OUT_DST_MAC, 6, 0, 0x00, 0x24, 0x1d, 0x04, 0x05, 0x06)                     \
  R(DIRECTION, 1, 0, 0x01)                                                     \
  /* Fourth flow (ingress) */                                                  \
  FIXED_FLOW_ENTITIES(R)                                                       \
  R(IPV4_SRC_ADDR, 4, 0, 66, 220, 152, 19)                                     \
  R(IPV4_SRC_ADDR, 4, 0, 66, 220, 152, 20)                                     \
  R(IP_PROTOCOL_VERSION, 1, 0, 0x04)                                           \
  R(L4_SRC_PORT, 2, 0, 0xd5, 0xb9)                                             \
  R(L4_DST_PORT, 2, 0, 0x01, 0xbb)                                             \
  R(IN_SRC_MAC, 6, 0, 0x00, 0x24, 0x14, 0x01, 0x02, 0x03)                      \
  R(IN_DST_MAC, 6, 0, 0x00, 0x22, 0x55, 0x04, 0x05, 0x06)                      \
  R(OUT_DST_MAC, 6, 0, 0x00, 0x24, 0x1d, 0x04, 0x05, 0x06)                     \
  R(DIRECTION, 1, 0, 0x00)                                                     \
  /* Fourth flow (egress) */                                                   \
  FIXED_FLOW_ENTITIES(R)                                                       \
  R(IPV4_SRC_ADDR, 4, 0, 66, 220, 152, 19)                                     \
  R(IPV4_SRC_ADDR, 4, 0, 66, 220, 152, 20)                                     \
  R(IP_PROTOCOL_VERSION, 1, 0, 0x04)                                           \
  R(L4_SRC_PORT, 2, 0, 0xd5, 0xb9)                                             \
  R(L4_DST_PORT, 2, 0, 0x01, 0xbb)                                             \
  R(IN_SRC_MAC, 6, 0, 0x00, 0x24, 0x14, 0x01, 0x02, 0x03)                      \
  R(IN_DST_MAC, 6, 0, 0x00, 0x22, 0x55, 0x04, 0x05, 0x06)                      \
  R(OUT_DST_MAC, 6, 0, 0x00, 0x24, 0x1d, 0x04, 0x05, 0x06)                     \
  R(DIRECTION, 1, 0, 0x01)

static const struct checkdata_value checkdata_values_span_egress[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "direction", .value="egress"},
	{.key = "client_mac", .value="00:22:55:04:05:06"},
};

static const struct checkdata_value checkdata_values_span_ingress[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "direction", .value="ingress"},
	{.key = "client_mac", .value="00:24:14:01:02:03"},
};

static const struct checkdata_value checkdata_values_span_internal[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "direction", .value="internal"},
	{.key = "client_mac", .value="00:22:55:04:05:06"},
};

static const struct checkdata_value checkdata_values_nospan_egress[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "direction", .value="egress"},
	{.key = "client_mac", .value="00:24:1d:04:05:06"},
};

#define checkdata_values_nospan_ingress checkdata_values_span_ingress

static const struct checkdata_value checkdata_values_nospan_internal[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "direction", .value="internal"},
	{.key = "client_mac", .value="00:24:1d:04:05:06"},
};

static const struct checkdata checkdata_span_true[] = {
	{.size = RD_ARRAYSIZE(checkdata_values_span_ingress), .checks=checkdata_values_span_ingress},
	{.size = RD_ARRAYSIZE(checkdata_values_span_ingress), .checks=checkdata_values_span_ingress},
	{.size = RD_ARRAYSIZE(checkdata_values_span_egress), .checks=checkdata_values_span_egress},
	{.size = RD_ARRAYSIZE(checkdata_values_span_egress), .checks=checkdata_values_span_egress},
	{.size = RD_ARRAYSIZE(checkdata_values_span_internal), .checks=checkdata_values_span_internal},
	{.size = RD_ARRAYSIZE(checkdata_values_span_internal), .checks=checkdata_values_span_internal},
	{.size = RD_ARRAYSIZE(checkdata_values_span_ingress), .checks=checkdata_values_span_ingress},
	{.size = RD_ARRAYSIZE(checkdata_values_span_egress), .checks=checkdata_values_span_egress},
};

static const struct checkdata checkdata_span_false[] = {
	{.size = RD_ARRAYSIZE(checkdata_values_nospan_ingress), .checks=checkdata_values_nospan_ingress},
	{.size = RD_ARRAYSIZE(checkdata_values_nospan_ingress), .checks=checkdata_values_nospan_ingress},
	{.size = RD_ARRAYSIZE(checkdata_values_nospan_egress), .checks=checkdata_values_nospan_egress},
	{.size = RD_ARRAYSIZE(checkdata_values_nospan_egress), .checks=checkdata_values_nospan_egress},
	{.size = RD_ARRAYSIZE(checkdata_values_nospan_internal), .checks=checkdata_values_nospan_internal},
	{.size = RD_ARRAYSIZE(checkdata_values_nospan_internal), .checks=checkdata_values_nospan_internal},
	{.size = RD_ARRAYSIZE(checkdata_values_nospan_ingress), .checks=checkdata_values_nospan_ingress},
	{.size = RD_ARRAYSIZE(checkdata_values_nospan_egress), .checks=checkdata_values_nospan_egress},
};

static int prepare_test_nf10_mac_direction(void **state) {
	static const IPFIX_TEMPLATE(v10Template, TEST_FLOW_HEADER,
			TEST_TEMPLATE_ID, FLOW_ENTITIES);
		static const IPFIX_FLOW(v10Flow, TEST_FLOW_HEADER, TEST_TEMPLATE_ID,
			FLOW_ENTITIES);

#define TEST(config_path, nf_dev_ip, mrecord, mrecord_size, checks,            \
								checks_size) { \
		.config_json_path = config_path,                               \
		.netflow_src_ip = nf_dev_ip, .netflow_dst_port = 2055,         \
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
			checkdata_span_true, RD_ARRAYSIZE(checkdata_span_true)),
		TEST_TEMPLATE_FLOW(NULL, 0x04030301,
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			checkdata_span_false,
			RD_ARRAYSIZE(checkdata_span_false)),
		TEST_TEMPLATE_FLOW(NULL, 0x04030401,
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			checkdata_span_false,
			RD_ARRAYSIZE(checkdata_span_false)),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

/// @todo should this be 3 different tests?
int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(testFlow,
						prepare_test_nf10_mac_direction,
						check_flow),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
