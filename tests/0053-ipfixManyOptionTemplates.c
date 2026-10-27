/*
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

/*
	Regression test: an IPFIX options template set can carry several
	option templates. All of them must be registered, not only the first
	one. Here the selector names template is the second one of the set,
	and it has a private enterprise field that must be skipped.
 */

#define TEST_TEMPLATE_ID 1025
#define OPTIONS_TEMPLATE_ID_1 300
#define OPTIONS_TEMPLATE_ID_2 301

#define TEST_IPFIX_FLOW_HEADER \
	.unix_secs = constexpr_be32toh(1467220140), \
	.flow_sequence = constexpr_be32toh(12372811), \
	.observation_id = constexpr_be32toh(2),

#define FLOW_ENTITIES(RT, R) \
	RT(IPV4_SRC_ADDR, 4, 0, 10, 13, 94, 223) \
	RT(SELECTOR_ID, 4, 0, UINT32_TO_UINT8_ARR(1)) \
	RT(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	RT(IN_PKTS, 8, 0, UINT64_TO_UINT8_ARR(263))

#define OPTION_TEMPLATE_SET_BYTES \
	/* Options template set */ \
	UINT16_TO_UINT8_ARR(3), UINT16_TO_UINT8_ARR(4 + 14 + 22), \
	/* 1st option template: interface names */ \
	UINT16_TO_UINT8_ARR(OPTIONS_TEMPLATE_ID_1), \
	UINT16_TO_UINT8_ARR(2), UINT16_TO_UINT8_ARR(1), \
	UINT16_TO_UINT8_ARR(INPUT_SNMP), UINT16_TO_UINT8_ARR(4), \
	UINT16_TO_UINT8_ARR(82 /* IF_NAME */), UINT16_TO_UINT8_ARR(4), \
	/* 2nd option template: selector names + a private field */ \
	UINT16_TO_UINT8_ARR(OPTIONS_TEMPLATE_ID_2), \
	UINT16_TO_UINT8_ARR(3), UINT16_TO_UINT8_ARR(1), \
	UINT16_TO_UINT8_ARR(SELECTOR_ID), UINT16_TO_UINT8_ARR(4), \
	UINT16_TO_UINT8_ARR(SELECTOR_NAME | 0x8000), UINT16_TO_UINT8_ARR(2), \
		UINT32_TO_UINT8_ARR(12356), \
	UINT16_TO_UINT8_ARR(SELECTOR_NAME), UINT16_TO_UINT8_ARR(5)

#define OPTION_DATA_SET_BYTES \
	UINT16_TO_UINT8_ARR(OPTIONS_TEMPLATE_ID_2), \
	UINT16_TO_UINT8_ARR(4 + 11), \
	UINT32_TO_UINT8_ARR(1), \
	'x', 'x', /* private field, must be ignored */ \
	'o', 'n', 'e', 0, 0

#define IPFIX_RAW_PACKET(var, ...) \
struct { \
	IPFIXFlowHeader flowHeader; \
	uint8_t body[BYTE_ARRAY_SIZE(__VA_ARGS__)]; \
} __attribute__((packed)) var = { \
	.flowHeader = { \
		.version = constexpr_be16toh(10), \
		.len = constexpr_be16toh(sizeof(IPFIXFlowHeader) \
			+ BYTE_ARRAY_SIZE(__VA_ARGS__)), \
		TEST_IPFIX_FLOW_HEADER \
	}, .body = { __VA_ARGS__ } \
}

static int prepare_test_ipfix_many_option_templates(void **state) {
	static const IPFIX_TEMPLATE(ipfix_template, TEST_IPFIX_FLOW_HEADER,
		TEST_TEMPLATE_ID, FLOW_ENTITIES);
	static const IPFIX_FLOW(ipfix_flow, TEST_IPFIX_FLOW_HEADER,
		TEST_TEMPLATE_ID, FLOW_ENTITIES);
	static const IPFIX_RAW_PACKET(option_template, OPTION_TEMPLATE_SET_BYTES);
	static const IPFIX_RAW_PACKET(option_data, OPTION_DATA_SET_BYTES);

	static const struct checkdata_value checkdata_pre[] = {
		{.key = "selector_id", .value = "1"},
		{.key = "selector_name", .value = "1"},
	};
	static const struct checkdata_value checkdata_post[] = {
		{.key = "selector_id", .value = "1"},
		{.key = "selector_name", .value = "one"},
	};
	static const struct checkdata pre = {
		.size = RD_ARRAYSIZE(checkdata_pre), .checks = checkdata_pre};
	static const struct checkdata post = {
		.size = RD_ARRAYSIZE(checkdata_post), .checks = checkdata_post};

#define TEST(mrecord, mrecord_size, checks, checks_size, ...) {                \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size,            \
		.netflow_src_ip = 0x04030201, __VA_ARGS__                      \
	}

	struct test_params test_params[] = {
		TEST(&ipfix_template, sizeof(ipfix_template), NULL, 0,
			.config_json_path =
				"tests/0010-testAppIdEnrichment.json",
			.host_list_path = "./tests/0010-data/"),
		TEST(&ipfix_flow, sizeof(ipfix_flow), &pre, 1,),
		TEST(&option_template, sizeof(option_template), NULL, 0,),
		TEST(&option_data, sizeof(option_data), NULL, 0,),
		TEST(&ipfix_flow, sizeof(ipfix_flow), &post, 1,),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
			prepare_test_ipfix_many_option_templates),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
