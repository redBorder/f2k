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

struct TestV9Template{
	V9FlowHeader flowHeader;
	V9TemplateHeader flowSetHeader;
	V9TemplateDef templateHeader;
	V9FlowSet templateSet[10];
};

struct TestV9Flow{
	V9FlowHeader flowHeader;
	V9TemplateHeader flowSetHeader;
	const uint8_t buffer1[72];
	const uint8_t buffer2[72];
}__attribute__((packed));

#define TEST_FLOW_HEADER \
	.sys_uptime = constexpr_be32toh(12345), \
	.unix_secs = constexpr_be32toh(1382364130), \
	.flow_sequence = constexpr_be32toh(1080), \
	.source_id = constexpr_be32toh(1),

#define TEST_TEMPLATE_ID 259

#define T_WLAN_SSID \
	'l','o','c','a','l','-','w','i', \
	'f','i',0,  0,  0,  0,  0,  0,   \
	0,  0,  0,  0,  0,  0,  0,  0,   \
	0,  0,  0,  0,  0,  0,  0,  0,   \
	0

#define TEST_NF9_ENTITIES(RT, R) \
	RT(STA_MAC_ADDRESS, 6, 0, 0x00, 0x05, 0x69, 0x28, 0xb0, 0xc7) \
	RT(STA_IPV4_ADDRESS, 4, 0, 10, 13, 94, 223) \
	RT(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453)) \
	RT(WLAN_SSID, 33, 0, T_WLAN_SSID) \
	RT(DIRECTION, 1, 0, 0) \
	RT(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	RT(IN_PKTS, 8, 0,  UINT64_TO_UINT8_ARR(263)) \
	RT(98, 1, 0, 0) \
	RT(195, 1, 0, 0) \
	RT(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40) \
	R(STA_MAC_ADDRESS, 6, 0, 0x00, 0x05, 0x69, 0x28, 0xb0, 0xc7)  \
	R(STA_IPV4_ADDRESS, 4, 0, 8, 8, 8, 8) \
	R(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453)) \
	R(WLAN_SSID, 33, 0, T_WLAN_SSID) \
	R(DIRECTION, 1, 0, 0) \
	R(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	R(IN_PKTS, 8, 0, UINT64_TO_UINT8_ARR(263)) \
	R(98, 1, 0, 0) \
	R(195, 1, 0, 0) \
	R(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40)

static const struct checkdata_value checkdata1[] = {
	{.key="type", .value="netflowv9"},
	{.key="lan_ip", .value="10.13.94.223"},
	{.key="lan_ip_name", .value=NULL},
	{.key="lan_ip_net", .value=NULL},
	{.key="lan_ip_net_name", .value=NULL},
};

static const struct checkdata_value checkdata2[] = {
	{.key="type", .value="netflowv9"},
	{.key="lan_ip", .value="8.8.8.8"},
	{.key="lan_ip_name", .value=NULL},
	{.key="lan_ip_net", .value="8.8.8.0/24"},
	{.key="lan_ip_net_name", .value="google8"},
};

static int prepare_test_nf9_ip_enrichment(void **state) {
	static const NF9_TEMPLATE(v9Template, TEST_FLOW_HEADER,
		TEST_TEMPLATE_ID, TEST_NF9_ENTITIES);

	static const NF9_FLOW(v9Flow, TEST_FLOW_HEADER,
		TEST_TEMPLATE_ID, TEST_NF9_ENTITIES);

	static const struct checkdata sl1_checkdata[] = {
		{.size = RD_ARRAYSIZE(checkdata1), .checks = checkdata1},
		{.size = RD_ARRAYSIZE(checkdata2), .checks = checkdata2},
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
		[0] = TEST("./tests/0000-testFlowV5.json", "./tests/0009-data/",
				&v9Template, sizeof(v9Template),
				NULL, 0),

		[1] = TEST(NULL, NULL, &v9Flow, sizeof(v9Flow),
			sl1_checkdata, RD_ARRAYSIZE(sl1_checkdata)),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
					prepare_test_nf9_ip_enrichment),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
