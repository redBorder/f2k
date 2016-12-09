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

#define TEST_IPFIX_HEADER \
	.unix_secs = constexpr_be32toh(1382637021), \
	.flow_sequence = constexpr_be32toh(1080), \
	.observation_id = constexpr_be32toh(256),

#define TEST_TEMPLATE_ID 269

#define TEST_ENTITIES(RT, R) \
	RT(IPV4_SRC_ADDR, 4, 0, 10, 13, 122, 44) \
	RT(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19) \
	RT(IP_PROTOCOL_VERSION, 1, 0, 4) \
	RT(PROTOCOL, 1, 0, 6) \
	RT(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713)) \
	RT(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443)) \
	RT(FLOW_END_REASON, 1, 0, 3) \
	RT(BIFLOW_DIRECTION, 1, 0, 1) \
	RT(FLOW_SAMPLER_ID, 1, 0, 0) \
	RT(TRANSACTION_ID, 8, 0,  0x8f, 0x63, 0xf3, 0x40, 0x00, 0x01, 0x00, 0x00) \
	RT(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453)) \
	RT(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(2744)) \
	RT(IN_PKTS, 4, 0,  UINT32_TO_UINT8_ARR(31)) \
	RT(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(267193024)) \
	RT(LAST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(267261952))


static const struct checkdata_value checkdata_values1[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "src", .value="10.13.122.44"},
	{.key = "dst", .value="66.220.152.19"},
	{.key = "ip_protocol_version", .value="4"},
	{.key = "l4_proto", .value="6"},
	{.key = "src_port", .value="54713"},
	{.key = "dst_port", .value="443"},
	{.key = "flow_end_reason", .value="end of flow"},
	{.key = "biflow_direction", .value="initiator"},
	{.key = "application_id", .value=NULL},

	{.key = "sensor_ip", .value="4.3.2.1"},
	{.key = "sensor_name", .value="FlowTest"},
	{.key = "bytes", .value="2744"},
	{.key = "pkts", .value="31"},
	{.key = "first_switched", .value="1382636953"},
	{.key = "timestamp", .value="1382637021"},
};

static const struct checkdata sl1_checkdata = {
	.checks = checkdata_values1,
	.size = RD_ARRAYSIZE(checkdata_values1)
};

static int prepare_test_ipfix(void **state) {
	static const IPFIX_TEMPLATE(v10Template, TEST_IPFIX_HEADER,
                TEST_TEMPLATE_ID, TEST_ENTITIES);
	static const IPFIX_FLOW(v10Flow, TEST_IPFIX_HEADER,
                TEST_TEMPLATE_ID, TEST_ENTITIES);

#define TEST(mrecord, mrecord_size, checks, checks_size, ...) { \
		.netflow_src_ip = 0x04030201,                                  \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size,            \
		__VA_ARGS__ \
	}

	struct test_params test_params[] = {
		[0] = TEST(&v10Template, sizeof(v10Template), NULL, 0,
			.config_json_path = "./tests/0000-testFlowV5.json"),

		[1] = TEST(&v10Flow, sizeof(v10Flow), &sl1_checkdata, 1,),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

// Test template+flow in the same packet
static int prepare_test_ipfix_template_flow(void **state) {
	static const IPFIX_TEMPLATE_FLOW(pkt, TEST_IPFIX_HEADER,
		TEST_TEMPLATE_ID, TEST_ENTITIES);

	struct test_params test_params[] = {
		TEST(&pkt, sizeof(pkt), &sl1_checkdata, 1,
			.config_json_path = "./tests/0000-testFlowV5.json"),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, prepare_test_ipfix),
		cmocka_unit_test_setup(testFlow,
			prepare_test_ipfix_template_flow),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}

