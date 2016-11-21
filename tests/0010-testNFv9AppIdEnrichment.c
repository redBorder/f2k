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

#define WLAN_SSID_CHARS \
	0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x2d, /* WLAN_SSID: "local-wifi" */ \
	0x77, 0x69, 0x66, 0x69, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00

#define APP_ID_ENTITIES(RT, R) \
	RT(STA_MAC_ADDRESS, 6, 0, 0x00, 0x05, 0x69, 0x28, 0xb0, 0xc7) \
	RT(STA_IPV4_ADDRESS, 4, 0, 10, 13, 94, 223) \
	RT(APPLICATION_ID, 4, 0, UINT32_TO_UINT8_ARR(0)) \
	RT(WLAN_SSID, 33, 0,  WLAN_SSID_CHARS) \
	RT(DIRECTION, 1, 0, 0) \
	RT(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	RT(IN_PKTS, 8, 0, UINT64_TO_UINT8_ARR(263)) \
	RT(98, 1, 0, 0) \
	RT(195, 1, 0, 0) \
	RT(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40) \
		/* ****************************** */ \
	R(STA_MAC_ADDRESS, 6, 0, 0x00, 0x05, 0x69, 0x28, 0xb0, 0xc7) \
	R(STA_IPV4_ADDRESS, 4, 0, 10, 13, 94, 223) \
	R(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453)) \
	R(WLAN_SSID, 33, 0,  WLAN_SSID_CHARS) \
	R(DIRECTION, 1, 0, 0) \
	R(BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	R(PKTS, 8, 0, UINT64_TO_UINT8_ARR(263)) \
	R(98, 1, 0, 0) \
	R(195, 1, 0, 0) \
	R(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40) \
		/* ****************************** */ \
	R(STA_MAC_ADDRESS, 6, 0, 0x00, 0x05, 0x69, 0x28, 0xb0, 0xc7) \
	R(STA_IPV4_ADDRESS, 4, 0, 10, 13, 94, 223) \
	R(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(3, 53)) \
	R(WLAN_SSID, 33, 0,  WLAN_SSID_CHARS) \
	R(DIRECTION, 1, 0, 0) \
	R(BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	R(PKTS, 8, 0, UINT64_TO_UINT8_ARR(263)) \
	R(98, 1, 0, 0) \
	R(195, 1, 0, 0) \
	R(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40)

#define TEST_TEMPLATE_ID 1025

#define TEST_FLOW_HEADER \
	.unix_secs = constexpr_be32toh(1467220140), \
	.flow_sequence = constexpr_be32toh(12372811), \

static const struct checkdata_value checkdata1[] = {
	{.key = "type", .value="netflowv9"},
	{.key = "application_id", .value=NULL},
	{.key = "application_id_name", .value=NULL},
	{.key = "engine_id", .value=NULL},
	{.key = "engine_id_name", .value=NULL},
};

static const struct checkdata_value checkdata2[] = {
	{.key="type", .value="netflowv9"},
	{.key="application_id", .value=NULL},
	{.key="application_id_name", .value="ssl"},
	{.key="engine_id", .value=NULL},
	{.key="engine_id_name", .value="PANA-L7"},
};

static const struct checkdata_value checkdata3[] = {
	{.key = "type", .value="netflowv9"},
	{.key = "application_id", .value=NULL},
	{.key = "application_id_name", .value="dns"},
	{.key = "engine_id", .value=NULL},
	{.key = "engine_id_name", .value="IANA-L4"},
};

static int prepare_test_nf9_appid_enrichment(void **state) {
	static const NF9_TEMPLATE(template, TEST_FLOW_HEADER,
		TEST_TEMPLATE_ID, APP_ID_ENTITIES);
	static const NF9_FLOW(flow, TEST_FLOW_HEADER, TEST_TEMPLATE_ID,
		APP_ID_ENTITIES);

	static const struct checkdata sl1_checkdata[] = {
		{.size = RD_ARRAYSIZE(checkdata1), .checks = checkdata1},
		{.size = RD_ARRAYSIZE(checkdata2), .checks = checkdata2},
		{.size = RD_ARRAYSIZE(checkdata3), .checks = checkdata3},
	};

#define TEST(config_path, mhosts_db_path, mrecord, mrecord_size, checks,       \
								checks_size) { \
		.config_json_path = config_path,                               \
		.host_list_path = mhosts_db_path,                              \
		.netflow_src_ip = 0x04030201,                                  \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size             \
	}

	struct test_params test_params[] = {
		[0] = TEST("./tests/0000-testFlowV5.json", "./tests/0010-data/",
				&template, sizeof(template),
				NULL, 0),

		[1] = TEST(NULL, NULL, &flow, sizeof(flow),
			sl1_checkdata, RD_ARRAYSIZE(sl1_checkdata)),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(testFlow,
					prepare_test_nf9_appid_enrichment,
					check_flow),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
