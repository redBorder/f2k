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

#include <librd/rd.h>

#include <setjmp.h>
#include <cmocka.h>

static const char t_config_path[] = "./tests/0000-testFlowV5.json";
#define FLOW_HEADER \
	.sys_uptime = constexpr_be32toh(12345), \
	.unix_secs = constexpr_be32toh(1382364130), \
	.flow_sequence = constexpr_be32toh(1080), \
	.source_id = constexpr_be32toh(1)
#define TEMPLATE_ID 259
#define T_WLAN_SSID \
	'l', 'o', 'c', 'a', 'l', '-', 'w', 'i', \
	'f', 'i', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00

// First flow
#define NF9_ENTITIES_BASE(X, T_BYTES, T_PKTS) \
	X(STA_MAC_ADDRESS, 6, 0, 0xb8, 0x17, 0xc2, 0x28, 0xb0, 0xc7) \
	X(STA_IPV4_ADDRESS, 4, 0, 10, 13, 94, 223) \
	X(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453)) \
	X(WLAN_SSID, 33, 0, T_WLAN_SSID) \
	X(DIRECTION, 1, 0, 0) \
	X(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(T_BYTES)) \
	X(IN_PKTS, 8, 0, UINT64_TO_UINT8_ARR(T_PKTS)) \
	X(PADDING_OCTETS /*It was 98*/, 1, 0, 0) \
	X(PADDING_OCTETS /*It was 195*/, 1, 0, 0) \
	X(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40)

#define NF9_CHECKDATA(T_BYTES, T_PKTS) { \
	{.key="type", .value="netflowv9"}, \
	{.key="client_mac", .value="b8:17:c2:28:b0:c7"}, \
	{.key="lan_ip", .value="10.13.94.223"}, \
	/* {.key="application_id", .value="13:453"}, */ \
	{.key="wireless_id", .value="local-wifi"}, \
	{.key="direction", .value="ingress"}, \
	{.key="sensor_ip", .value="4.3.2.1"}, \
	{.key="bytes", .value=T_BYTES}, {.key="pkts", .value=T_PKTS}}

static int test_nf9_0(void **state, const void *template, size_t template_size,
		const void *flow, size_t flow_size,
		const struct checkdata *checkdata, size_t checkdata_size) {

#define TEST(mrecord, mrecord_size, mcheckdata, mcheckdata_sz, ...) {          \
		.host_list_path = NULL, .netflow_src_ip = 0x04030201,          \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = mcheckdata, .checkdata_size = mcheckdata_sz,      \
		__VA_ARGS__}

#define TEST_TEMPLATE_FLOW(template, template_size, flow, flow_size,           \
		mcheckdata, mcheckdata_sz, ...)                                \
	TEST(template, template_size, NULL, 0, __VA_ARGS__),                   \
	TEST(flow, flow_size, mcheckdata, mcheckdata_sz,)

	struct test_params test_params[] = {
		TEST_TEMPLATE_FLOW(template, template_size,
			flow, flow_size, checkdata, checkdata_size,
			.config_json_path = t_config_path),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

/// Test 1-flow nf9 packet
static int test_nf9_1(void **state) {
#define NF9_ENTITIES(RT, R) NF9_ENTITIES_BASE(RT, 7603, 263)

	static const NF9_TEMPLATE(v9Template, FLOW_HEADER, TEMPLATE_ID,
		NF9_ENTITIES);
	static const NF9_FLOW(v9Flow, FLOW_HEADER, TEMPLATE_ID, NF9_ENTITIES);

#undef NF9_ENTITIES

	static const struct checkdata_value checkdata_values[] =
		NF9_CHECKDATA("7603", "263");

	static const struct checkdata checkdata = {
		.size = RD_ARRAYSIZE(checkdata_values),
		.checks = checkdata_values
	};

	return test_nf9_0(state, &v9Template, sizeof(v9Template),
		&v9Flow, sizeof(v9Flow), &checkdata, 1);
}

/// Test 2-flow nf9 packet
static int test_nf9_2(void **state) {
#define NF9_ENTITIES(RT, R) \
		NF9_ENTITIES_BASE(RT, 7603, 263) \
		NF9_ENTITIES_BASE(R, 7604, 264) \

	static const NF9_TEMPLATE(v9Template, FLOW_HEADER, TEMPLATE_ID,
		NF9_ENTITIES);
	static const NF9_FLOW(v9Flow, FLOW_HEADER, TEMPLATE_ID, NF9_ENTITIES);
#undef NF9_ENTITIES

	static const struct checkdata_value checkdata_values_1[] =
		NF9_CHECKDATA("7603", "263");
	static const struct checkdata_value checkdata_values_2[] =
		NF9_CHECKDATA("7604", "264");

#define CHECKS(values) {.size = RD_ARRAYSIZE(values), .checks = values}
	static const struct checkdata checkdata[] = {
		CHECKS(checkdata_values_1),
		CHECKS(checkdata_values_2),
	};
#undef CHECKS

	return test_nf9_0(state, &v9Template, sizeof(v9Template),
		&v9Flow, sizeof(v9Flow),
		checkdata, RD_ARRAYSIZE(checkdata));
}

static int test_nf9_template_flow(void **state) {
#define NF9_ENTITIES(RT, R) NF9_ENTITIES_BASE(RT, 7603, 263)
	static const NF9_TEMPLATE_FLOW(flow, FLOW_HEADER, TEMPLATE_ID,
		NF9_ENTITIES);

	static const struct checkdata_value checkdata_values[] =
		NF9_CHECKDATA("7603", "263");

	static const struct checkdata checkdata = {
		.size = RD_ARRAYSIZE(checkdata_values),
		.checks = checkdata_values
	};

	static const struct test_params test_params[] = {
		TEST(&flow, sizeof(flow), &checkdata, 1,
			.config_json_path = t_config_path),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, test_nf9_1),
		cmocka_unit_test_setup(testFlow, test_nf9_2),
		cmocka_unit_test_setup(testFlow, test_nf9_template_flow),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}

